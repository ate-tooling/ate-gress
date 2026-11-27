package ctl

import (
	"errors"
	"flag"
	"fmt"
	"text/tabwriter"

	"github.com/ate-tooling/ate-gress/internal/policy"
	"github.com/ate-tooling/ate-gress/internal/policyfile"
)

// explanation is the result of `ategressctl explain`, and its JSON output.
type explanation struct {
	Actor  string `json:"actor"`
	Method string `json:"method"`
	URL    string `json:"url"`
	// Authority and Path are the :authority and :path the URL was split
	// into, and Host the name Decide looked up: the authority in lowercase,
	// without a port or trailing dot. Host is empty when the authority is
	// not one Decide accepts.
	Authority string `json:"authority"`
	Path      string `json:"path"`
	Host      string `json:"host,omitempty"`
	decision
	// LogAllowed is set when the request would be logged at INFO because a
	// claiming policy has logAllowed.
	LogAllowed bool `json:"logAllowed"`
	// Claims lists the policies that claim the host for the actor, in the
	// order Decide considers them.
	Claims []claimReport `json:"claims"`
}

type claimReport struct {
	Policy     string `json:"policy"`
	Mode       string `json:"mode"`
	LogAllowed bool   `json:"logAllowed"`
	// Rejected is set for a policy the compiler rejected, which claims the
	// host with no routes.
	Rejected bool `json:"rejected,omitempty"`
	// Alone is what the decision would be if this were the only policy.
	Alone decision `json:"alone"`
}

// reasonText says what each reason means, in terms of the policies.
var reasonText = map[policy.Reason]string{
	policy.ReasonUnclaimed:     "no policy that selects the actor claims the host, so the request is left to Substrate's EgressPolicy",
	policy.ReasonRoute:         "a route matched the method and path",
	policy.ReasonNoRoute:       "the host is claimed for the actor and no route matches the method and path",
	policy.ReasonPath:          "the host is claimed for the actor and the path is one an upstream could read differently, such as an encoded slash, a dot segment or an empty segment",
	policy.ReasonInvalidPolicy: "the host is claimed for the actor only by policies the compiler rejected, which allow nothing and still claim their hosts",
	policy.ReasonAuthority:     "the authority is not a hostname or IP literal with an optional port",
}

const explainHelp = `Decides one request as ate-gress would and says why: the decision and its
reason, the policy and path template that matched, and every policy that
claims the host for the actor, with what each would decide alone.

The URL is split into :authority and :path as written. Nothing is decoded or
cleaned, so a path a client would not normally send can be tried as is.

Exits 0 whatever the decision, and 1 if a policy is invalid.`

func runExplain(args []string, env Env) error {
	var actorFlag string
	c := newFlags(env, "explain", "-f <policies>... -a <atespace>/<name> <METHOD> <URL>", explainHelp, func(fs *flag.FlagSet) {
		fs.StringVar(&actorFlag, "a", "", "The `actor` sending the request, as <atespace>/<name>.")
		fs.StringVar(&actorFlag, "actor", "", "The same as -a.")
	})
	rest, err := c.parse(args)
	if err != nil {
		return err
	}
	if len(rest) != 2 {
		return errors.New("explain: give the request as <METHOD> <URL>")
	}
	if actorFlag == "" {
		return errors.New("explain: -a <atespace>/<name> is required")
	}
	actor, err := parseActor(actorFlag)
	if err != nil {
		return err
	}
	req, err := parseURL(rest[0], rest[1])
	if err != nil {
		return err
	}
	loaded, err := c.load("explain", env)
	if err != nil {
		return err
	}
	if len(loaded.invalid) > 0 {
		// A decision from a set no cluster would hold explains nothing.
		fmt.Fprintln(env.Stderr, "a cluster would not apply these policies as written:")
		printInvalid(env.Stderr, loaded.invalid)
		return errFailed{}
	}

	got, raw := decide(loaded.snap, actor, req)
	ex := explanation{
		Actor: actor.String(), Method: req.Method, URL: rest[1], Authority: req.Authority, Path: req.Path,
		decision: got, LogAllowed: raw.LogAllowed, Claims: []claimReport{},
	}
	host, claims, _ := loaded.snap.ClaimsFor(req.Authority, actor)
	ex.Host = host
	for _, claim := range claims {
		cr := claimReport{Policy: claim.Policy, Mode: "Enforce", LogAllowed: claim.LogAllowed, Rejected: claim.Rejected}
		if claim.Audit {
			cr.Mode = "Audit"
		}
		// Compiling the one policy and deciding against it asks Decide
		// itself, where matching its routes here would be a second
		// implementation.
		if d := loaded.set.Document(claim.Policy); d != nil {
			alone, _ := policy.Compile([]policyfile.Policy{d.Policy})
			cr.Alone, _ = decide(alone, actor, req)
		}
		ex.Claims = append(ex.Claims, cr)
	}

	if c.json() {
		return writeJSON(env.Stdout, ex)
	}
	printExplanation(env, ex)
	return nil
}

func printExplanation(env Env, ex explanation) {
	w := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(w, "%s\t%s\n", k, v)
		}
	}
	row("request", ex.Method+" "+ex.URL)
	row("actor", ex.Actor)
	row("decision", ex.Decision)
	row("reason", fmt.Sprintf("%s: %s", ex.Reason, reasonText[policy.Reason(ex.Reason)]))
	switch {
	case ex.Decision == outcomeAllow:
		row("policy", ex.Policy)
		row("template", ex.Template)
	case ex.Policy != "":
		// For a denied or audited request Decide names the first policy
		// that claimed the host, not one that matched.
		row("policy", ex.Policy+" (the first policy claiming the host; none allowed the request)")
	}
	if ex.Decision == outcomeAudit {
		row("audit", "allowed only because every policy claiming the host for this actor is in Audit mode; Enforce would deny it")
	}
	if ex.LogAllowed {
		row("logged", "at INFO: a claiming policy has logAllowed")
	}
	_ = w.Flush()

	out := env.Stdout
	switch {
	case ex.Host == "":
		return
	case len(ex.Claims) == 0:
		fmt.Fprintf(out, "\nNo policy claims %s for %s.\n", ex.Host, ex.Actor)
		return
	}
	fmt.Fprintf(out, "\nPolicies claiming %s for %s:\n", ex.Host, ex.Actor)
	w = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, c := range ex.Claims {
		mode := c.Mode
		if c.LogAllowed {
			mode += ", logAllowed"
		}
		if c.Rejected {
			mode += ", rejected"
		}
		alone := c.Alone.Decision + " (" + c.Alone.Reason
		if c.Alone.Template != "" {
			alone += ", " + c.Alone.Template
		}
		fmt.Fprintf(w, "  %s\t%s\talone: %s)\n", c.Policy, mode, alone)
	}
	_ = w.Flush()
	if hasMode(ex.Claims, "Enforce") && hasMode(ex.Claims, "Audit") {
		fmt.Fprintln(out, "\nAn Enforce policy claims the host, so the Audit policies' routes are not consulted.")
	}
}

func hasMode(claims []claimReport, mode string) bool {
	for _, c := range claims {
		if c.Mode == mode {
			return true
		}
	}
	return false
}
