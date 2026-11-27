// Package ctl implements the ategressctl command: checking EgressRoutePolicy
// files offline, with the code ate-gress decides requests with.
//
// Every decision it reports comes from policy.Compile and Snapshot.Decide,
// the functions the server runs, so what it says about a policy set is what a
// cluster holding that set would do.
package ctl

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/ate-tooling/ate-gress/internal/identity"
	"github.com/ate-tooling/ate-gress/internal/lint"
	"github.com/ate-tooling/ate-gress/internal/policy"
	"github.com/ate-tooling/ate-gress/internal/policyfile"
)

// Exit codes. They are part of the command's interface: scripts and CI jobs
// branch on them.
const (
	// ExitOK: the command ran and found nothing wrong.
	ExitOK = 0
	// ExitFailed: the command ran and the policies are not as wanted: a test
	// case failed, a policy is invalid, or lint found something at or above
	// --fail-on.
	ExitFailed = 1
	// ExitUsage: the command could not do its job: bad flags, an unreadable
	// or malformed file, or a test file that makes no sense.
	ExitUsage = 2
)

const usage = `ategressctl checks EgressRoutePolicy files offline, with the code ate-gress
decides requests with.

Usage:
  ategressctl test    [-f <policies>]... <test file>...
  ategressctl explain  -f <policies>...  -a <atespace>/<name> <METHOD> <URL>
  ategressctl lint     -f <policies>...  [--egress-policy [<atespace>/<name>=]<file>]...
  ategressctl version

-f names a file of YAML or JSON documents, a directory (searched recursively),
or - for stdin, and may be repeated. Every command takes -o text|json.
Run "ategressctl <command> -h" for a command's flags.

Exit codes: 0 nothing wrong; 1 a test failed, a policy is invalid, or lint
found something; 2 bad usage or unreadable input.
`

// Env is what a command reads and writes.
type Env struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	// Version is what `ategressctl version` prints.
	Version string
}

// Run runs ategressctl with args, the command line after the program name,
// and returns its exit code.
func Run(args []string, env Env) int {
	if len(args) == 0 {
		fmt.Fprint(env.Stderr, usage)
		return ExitUsage
	}
	var err error
	switch cmd, rest := args[0], args[1:]; cmd {
	case "test":
		err = runTest(rest, env)
	case "explain":
		err = runExplain(rest, env)
	case "lint":
		err = runLint(rest, env)
	case "version":
		fmt.Fprintln(env.Stdout, env.Version)
	case "help", "-h", "-help", "--help":
		fmt.Fprint(env.Stdout, usage)
	default:
		fmt.Fprintf(env.Stderr, "ategressctl: unknown command %q\n\n%s", cmd, usage)
		return ExitUsage
	}
	var failed errFailed
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return ExitOK
	case errors.As(err, &failed):
		return ExitFailed
	}
	// The flag package has already printed its own errors.
	if !errors.Is(err, errFlags) {
		fmt.Fprintf(env.Stderr, "ategressctl: %v\n", err)
	}
	return ExitUsage
}

// errFailed is returned by a command that ran and reported a failure, which
// it has already printed.
type errFailed struct{}

func (errFailed) Error() string { return "failed" }

// errFlags marks a flag-parsing error, which the flag package reports itself.
var errFlags = errors.New("bad flags")

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// common holds the flags every command takes.
type common struct {
	fs       *flag.FlagSet
	policies stringList
	output   string
}

func newFlags(env Env, name, synopsis, help string) *common {
	c := &common{fs: flag.NewFlagSet("ategressctl "+name, flag.ContinueOnError)}
	c.fs.SetOutput(env.Stderr)
	c.fs.Usage = func() {
		fmt.Fprintf(env.Stderr, "Usage: ategressctl %s %s\n\n%s\n\nFlags:\n", name, synopsis, help)
		c.fs.PrintDefaults()
	}
	c.fs.Var(&c.policies, "f", "EgressRoutePolicy `file`, directory, or - for stdin; repeatable.")
	c.fs.StringVar(&c.output, "o", "text", "Output `format`: text or json.")
	return c
}

// parse parses args, letting flags and positional arguments mix as they do
// in kubectl, which the flag package alone stops at the first positional.
func (c *common) parse(args []string) ([]string, error) {
	var positional []string
	for {
		if err := c.fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, errFlags
		}
		if c.fs.NArg() == 0 {
			break
		}
		positional = append(positional, c.fs.Arg(0))
		args = c.fs.Args()[1:]
	}
	if c.output != "text" && c.output != "json" {
		return nil, fmt.Errorf("-o %q: the output format is text or json", c.output)
	}
	return positional, nil
}

func (c *common) json() bool { return c.output == "json" }

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// policies is a policy set and the snapshot ate-gress would build from it.
type policies struct {
	set  *policyfile.Set
	snap *policy.Snapshot
	// invalid lists the policies a cluster would not apply as written. When
	// it is not empty, commands that report decisions refuse to.
	//
	// snap does give a rejected policy its effect in a cluster: it allows
	// nothing and still claims its hosts. The refusal is not about that. The
	// compiler re-checks what the schema checks, so a policy it rejects is
	// one the API server refuses too, and a set holding one is not a set a
	// cluster with this CustomResourceDefinition can hold; it gets there only
	// past an older schema. Deciding against it would answer a question about
	// a cluster that cannot exist, and the policy needs fixing before any
	// answer matters.
	invalid []lint.Finding
}

func loadPolicies(paths []string, stdin io.Reader) (*policies, error) {
	set, err := policyfile.Load(paths, stdin)
	if err != nil {
		return nil, err
	}
	snap, _, invalid := lint.Validate(set)
	return &policies{set: set, snap: snap, invalid: invalid}, nil
}

// parseActor reads "<atespace>/<name>". It accepts what the server's identity
// parser accepts, because a request from any other actor never reaches
// Decide: the server denies it with reason "identity".
func parseActor(s string) (identity.Actor, error) {
	a, err := identity.ParseActor(s)
	if err != nil {
		return identity.Actor{}, fmt.Errorf("actor %q is not <atespace>/<name>, each a lowercase DNS label", s)
	}
	return a, nil
}

// request is an HTTP request as Decide takes it.
type request struct {
	Method    string
	Authority string
	// Path is the :path pseudo-header: the path and any query, exactly as
	// written, so that a test can send what a hostile actor would.
	Path string
}

// parseURL splits an http or https URL into the :authority and :path a
// client would send. It splits and nothing more: no decoding, cleaning or
// lowercasing, because Decide's handling of an odd authority or path is the
// thing under test.
func parseURL(method, raw string) (request, error) {
	if method == "" || strings.ContainsAny(method, " \t") {
		return request{}, fmt.Errorf("method %q is not an HTTP method", method)
	}
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok || scheme != "http" && scheme != "https" {
		return request{}, fmt.Errorf("URL %q does not start with http:// or https://", raw)
	}
	// A fragment is never sent.
	rest, _, _ = strings.Cut(rest, "#")
	authority, path := rest, "/"
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		authority, path = rest[:i], rest[i:]
		if path[0] == '?' {
			path = "/" + path
		}
	}
	if authority == "" {
		return request{}, fmt.Errorf("URL %q has no host", raw)
	}
	return request{Method: method, Authority: authority, Path: path}, nil
}

// Outcomes of a decision, as test files and reports name them.
const (
	outcomeAllow = "allow"
	outcomeDeny  = "deny"
	outcomeAudit = "audit"
)

// decision is a policy.Decision in the form reports print.
type decision struct {
	// Decision is allow, deny, or audit: allowed, but only because the
	// policies that would have denied it are in Audit mode.
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
	Policy   string `json:"policy,omitempty"`
	Template string `json:"template,omitempty"`
}

func decide(snap *policy.Snapshot, actor identity.Actor, r request) (decision, policy.Decision) {
	d := snap.Decide(policy.Request{Actor: actor, Method: r.Method, Authority: r.Authority, Path: r.Path})
	out := decision{Decision: outcomeDeny, Reason: string(d.Reason), Policy: d.Policy, Template: d.Pattern}
	switch {
	case d.Audited:
		out.Decision = outcomeAudit
	case d.Allowed:
		out.Decision = outcomeAllow
	}
	return out, d
}

func (d decision) String() string {
	parts := []string{"reason " + d.Reason}
	if d.Policy != "" {
		parts = append(parts, "policy "+d.Policy)
	}
	if d.Template != "" {
		parts = append(parts, "template "+d.Template)
	}
	return d.Decision + " (" + strings.Join(parts, ", ") + ")"
}

// printInvalid reports the policies a cluster would not apply.
func printInvalid(w io.Writer, invalid []lint.Finding) {
	for _, f := range invalid {
		fmt.Fprintln(w, formatFinding(f))
	}
}

func formatFinding(f lint.Finding) string {
	where := f.File
	if f.Document > 1 {
		where = fmt.Sprintf("%s#%d", f.File, f.Document)
	}
	if f.Policy != "" {
		where += ": " + f.Policy
	}
	if f.Field != "" {
		where += ": " + f.Field
	}
	return fmt.Sprintf("%s: %s %s (%s): %s", where, f.Severity, f.Code, f.Name, f.Message)
}
