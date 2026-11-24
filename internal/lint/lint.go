// Package lint finds mistakes in a set of EgressRoutePolicy objects that the
// API server and the compiler accept, or that only show once the set is read
// together with the actors' Substrate EgressPolicy.
//
// It reports only what it can prove from the policies. Where a finding
// depends on something the policies leave open, such as whether two glob
// selectors ever select the same actor, the finding says "may" and has its
// own code.
package lint

import (
	"cmp"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/ate-tooling/ate-gress/internal/egresspolicy"
	"github.com/ate-tooling/ate-gress/internal/identity"
	"github.com/ate-tooling/ate-gress/internal/pathmatch"
	"github.com/ate-tooling/ate-gress/internal/policy"
	"github.com/ate-tooling/ate-gress/internal/policyfile"
)

// Severity ranks a finding.
type Severity string

const (
	// Error is a policy the cluster would refuse or the compiler would
	// reject.
	Error Severity = "error"
	// Warning is a policy that provably does not do what it says.
	Warning Severity = "warning"
	// Info is something worth a look that may well be intended.
	Info Severity = "info"
)

// Rank orders severities, Error highest.
func (s Severity) Rank() int {
	switch s {
	case Error:
		return 3
	case Warning:
		return 2
	case Info:
		return 1
	}
	return 0
}

// Check identifies a kind of finding. Codes and names are stable: scripts
// match on them.
type Check struct {
	Code     string
	Name     string
	Severity Severity
	// Summary is one line for the documentation and `ategressctl lint
	// --list`.
	Summary string
}

var (
	Schema = Check{"ERP001", "schema", Error,
		"The API server would reject the policy: it fails the CustomResourceDefinition's schema."}
	DuplicateItem = Check{"ERP002", "duplicate-item", Error,
		"A method, path, host or selector glob is listed twice; the API server rejects the policy."}
	Compile = Check{"ERP003", "compile", Error,
		"The compiler rejects the policy: it allows nothing, and still claims its hosts for the actors it selects."}
	AuditShadowed = Check{"ERP101", "audit-shadowed", Warning,
		"An Audit policy never has effect on a host: an Enforce policy claims the host for every actor it selects."}
	AuditPartlyShadowed = Check{"ERP102", "audit-partly-shadowed", Warning,
		"An Audit policy has no effect on a host for some of its actors: an Enforce policy claims the host for them too."}
	AuditMaybeShadowed = Check{"ERP103", "audit-maybe-shadowed", Info,
		"An Audit policy may have no effect on a host: an Enforce policy claims it, and their selectors may overlap."}
	RedundantPath = Check{"ERP201", "redundant-path", Warning,
		"A path template allows nothing that another template of the same policy and host does not already allow."}
	OverlappingRoutes = Check{"ERP202", "overlapping-routes", Info,
		"Two routes of a policy allow the same paths for some of the same methods."}
	TLSPassthrough = Check{"ERP301", "tls-passthrough", Warning,
		"A claimed host is on a tls_passthrough rule of the given EgressPolicy, so ate-gress never sees that traffic."}
	HostNotReached = Check{"ERP302", "host-not-reached", Info,
		"No http or https rule of the given EgressPolicy reaches a claimed host, so the claim has no effect for that actor."}
)

// Checks lists every check, in code order.
var Checks = []Check{
	Schema, DuplicateItem, Compile,
	AuditShadowed, AuditPartlyShadowed, AuditMaybeShadowed,
	RedundantPath, OverlappingRoutes,
	TLSPassthrough, HostNotReached,
}

// Finding is one thing lint found.
type Finding struct {
	Code     string   `json:"code"`
	Name     string   `json:"name"`
	Severity Severity `json:"severity"`
	// Policy is the EgressRoutePolicy the finding is about, File the file
	// it was read from, Document the position of its YAML document in that
	// file, from 1, and Field the path of the field in it.
	Policy   string `json:"policy"`
	File     string `json:"file"`
	Document int    `json:"document"`
	Field    string `json:"field,omitempty"`
	Message  string `json:"message"`

	// doc is the position of the policy in the set, which findings are
	// reported in the order of.
	doc int
}

// EgressPolicy is a Substrate EgressPolicy to check claimed hosts against.
type EgressPolicy struct {
	File   string
	Policy *egresspolicy.Policy
	// Actor is the actor the policy belongs to, when the caller knows it.
	// The manifest itself names at most the atespace.
	Actor *identity.Actor
}

// Validate reports the policies of set that a cluster would not apply as
// written: those the API server would reject (Schema, DuplicateItem) and those
// the compiler rejects (Compile). It returns the snapshot policy.Compile
// builds from the set, which is what ate-gress would serve from, and the
// compiler's results in the order of set.Documents.
//
// A policy the compiler rejects is still in that snapshot, as a claim on its
// hosts with no routes, and the Compile finding says what it claims.
func Validate(set *policyfile.Set) (*policy.Snapshot, []policy.Result, []Finding) {
	l := &linter{}
	snap, results := policy.Compile(set.Policies())
	for i := range set.Documents {
		d := &set.Documents[i]
		for _, e := range d.Invalid {
			check := Schema
			if e.Duplicate {
				check = DuplicateItem
			}
			l.add(check, d, e.Field, "%s", e.Message)
		}
		if err := results[i].Err; err != nil {
			field, msg := splitCompileError(err.Error())
			l.add(Compile, d, field, "%s. %s", msg, results[i].Effect)
		}
	}
	return snap, results, l.findings
}

// Run lints set, and checks its claimed hosts against each of egress.
func Run(set *policyfile.Set, egress []EgressPolicy) []Finding {
	snap, results, invalid := Validate(set)
	l := &linter{findings: invalid}
	for i := range set.Documents {
		if results[i].Err == nil {
			l.routes(&set.Documents[i])
		}
	}
	// What follows reads the claims from the snapshot Compile built, so it is
	// about the claims ate-gress would actually hold.
	docs := make(map[string]*policyfile.Document, len(set.Documents))
	for i := range set.Documents {
		docs[set.Documents[i].Name()] = &set.Documents[i]
	}
	for _, host := range snap.Hosts() {
		claims := snap.Claims(host)
		l.audit(docs, host, claims)
		for _, e := range egress {
			l.egress(docs, host, claims, e)
		}
	}
	slices.SortStableFunc(l.findings, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(a.doc, b.doc), cmp.Compare(a.Code, b.Code), cmp.Compare(a.Field, b.Field))
	})
	return l.findings
}

type linter struct {
	findings []Finding
}

func (l *linter) add(c Check, d *policyfile.Document, field, format string, args ...any) {
	l.findings = append(l.findings, Finding{
		Code: c.Code, Name: c.Name, Severity: c.Severity,
		Policy: d.Name(), File: d.File, Document: d.Index, Field: field, Message: fmt.Sprintf(format, args...),
		doc: d.Order,
	})
}

var fieldRE = regexp.MustCompile(`^[A-Za-z]+(\[\d+\])?(\.[A-Za-z]+(\[\d+\])?)*$`)

// splitCompileError turns a compiler error, which starts with the fields it
// descended through ("hosts[0].routes[1]: paths: ..."), into a field path and
// the rest.
func splitCompileError(msg string) (field, rest string) {
	field = "spec"
	for {
		head, tail, ok := strings.Cut(msg, ": ")
		if !ok || !fieldRE.MatchString(head) {
			return field, msg
		}
		field, msg = field+"."+head, tail
	}
}

// hostField returns the path of host in d's spec.
func hostField(d *policyfile.Document, host string) string {
	i := slices.IndexFunc(d.Policy.Spec.Hosts, func(h policyfile.Host) bool { return h.Host == host })
	return fmt.Sprintf("spec.hosts[%d]", i)
}

// routes looks for path templates that add nothing within one host of one
// policy. Routes only allow, so a template is redundant exactly when another
// one allows every request it does: it matches every path the first matches,
// for every method of the first's route.
func (l *linter) routes(d *policyfile.Document) {
	type entry struct {
		route, path int
		methods     []policyfile.Method
		tmpl        *pathmatch.Template
	}
	for h, host := range d.Policy.Spec.Hosts {
		var entries []entry
		for r, route := range host.Routes {
			for p, pattern := range route.Paths {
				tmpl, err := pathmatch.Compile(pattern, route.CaseInsensitive)
				if err != nil {
					return // cannot happen: the policy compiled
				}
				entries = append(entries, entry{r, p, uniq(route.Methods), tmpl})
			}
		}
		for i, b := range entries {
			var partial *entry
			var shared []string
			redundant := false
			for j, a := range entries {
				if i == j || !a.tmpl.Covers(b.tmpl) {
					continue
				}
				if a.route == b.route && a.tmpl.String() == b.tmpl.String() {
					continue // the same path twice in one list: ERP002 has it
				}
				common := intersect(a.methods, b.methods)
				mutual := b.tmpl.Covers(a.tmpl)
				switch {
				case len(common) == len(b.methods):
					// Two templates that each make the other redundant are
					// one finding, on the later.
					if mutual && len(common) == len(a.methods) && j > i {
						continue
					}
					l.add(RedundantPath, d, fmt.Sprintf("spec.hosts[%d].routes[%d].paths[%d]", h, b.route, b.path),
						"%q is redundant: %s already allows everything it matches for %s",
						b.tmpl, describe(h, a.route, a.path, b.route, a.tmpl), strings.Join(methodNames(b.methods), ", "))
					redundant = true
				case len(common) > 0 && partial == nil && (!mutual || j < i):
					partial, shared = &entries[j], common
				}
				if redundant {
					break
				}
			}
			if !redundant && partial != nil {
				l.add(OverlappingRoutes, d, fmt.Sprintf("spec.hosts[%d].routes[%d].paths[%d]", h, b.route, b.path),
					"%q is already allowed for %s by %s; only its other methods add anything",
					b.tmpl, strings.Join(shared, ", "), describe(h, partial.route, partial.path, b.route, partial.tmpl))
			}
		}
	}
}

// describe names a template for a message about one in route `from`.
func describe(host, route, path, from int, tmpl *pathmatch.Template) string {
	if route == from {
		return fmt.Sprintf("%q in the same route", tmpl)
	}
	return fmt.Sprintf("%q (spec.hosts[%d].routes[%d].paths[%d])", tmpl, host, route, path)
}

func uniq(ms []policyfile.Method) []policyfile.Method {
	var out []policyfile.Method
	for _, m := range ms {
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out
}

func methodNames(ms []policyfile.Method) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = string(m)
	}
	return out
}

func intersect(a, b []policyfile.Method) []string {
	var out []string
	for _, m := range b {
		if slices.Contains(a, m) && !slices.Contains(out, string(m)) {
			out = append(out, string(m))
		}
	}
	return out
}

// audit looks for Audit policies that an Enforce policy overrides on host.
//
// Decide lets Audit policies decide a request only when no Enforce policy
// claims its host for its actor. As soon as one does, the request is allowed
// or denied by the Enforce policies' routes alone: an Audit policy's routes
// are not consulted, and nothing is recorded as an audit.
//
// A rejected Enforce policy is such a policy. It claims its hosts with no
// routes, for the actors its selector is read to select, so it shadows an
// Audit policy as a lockdown would. A rejected Audit policy has no routes to
// shadow and is not looked at: its Compile finding says what it claims.
func (l *linter) audit(docs map[string]*policyfile.Document, host string, claims []policy.Claim) {
	for _, p := range claims {
		if !p.Audit || p.Rejected {
			continue
		}
		d := docs[p.Policy]
		var partly, maybe []policy.Claim
		var example identity.Actor
		covered := false
		for _, q := range claims {
			if q.Audit {
				continue
			}
			if selectorCovers(q, p) {
				msg := fmt.Sprintf("never has effect on %s: %s claims the host for every actor this Audit policy selects, "+
					"and an Enforce policy always takes precedence, so these routes are never consulted and no audit is ever recorded", host, enforceName(q))
				if p.LogAllowed {
					msg += "; its logAllowed still applies"
				}
				l.add(AuditShadowed, d, hostField(d, host), "%s", msg)
				covered = true
				break
			}
			switch state, actor := selectorOverlap(p, q); state {
			case overlapSome:
				if len(partly) == 0 {
					example = actor
				}
				partly = append(partly, q)
			case overlapUnknown:
				maybe = append(maybe, q)
			}
		}
		if covered {
			continue
		}
		if len(partly) > 0 {
			l.add(AuditPartlyShadowed, d, hostField(d, host),
				"has no effect on %s for the actors that %s also selects, such as %s: an Enforce policy always takes precedence there, "+
					"so these routes are not consulted and no audit is recorded for them",
				host, quoted("Enforce policy", "Enforce policies", partly), example)
		}
		if len(maybe) > 0 {
			l.add(AuditMaybeShadowed, d, hostField(d, host),
				"may have no effect on %s for some actors: %s also claims the host, and whether the selectors can select the same actor could not be settled",
				host, quoted("Enforce policy", "Enforce policies", maybe))
		}
	}
}

// enforceName names an Enforce policy's claim for a message, and says when
// the policy was rejected, since it then shadows with a claim that allows
// nothing.
func enforceName(c policy.Claim) string {
	return "Enforce policy " + claimName(c)
}

func claimName(c policy.Claim) string {
	if c.Rejected {
		return fmt.Sprintf("%q (rejected: it allows nothing and still claims the host)", c.Policy)
	}
	return fmt.Sprintf("%q", c.Policy)
}

func quoted(singular, plural string, claims []policy.Claim) string {
	q := make([]string, len(claims))
	for i, c := range claims {
		q[i] = claimName(c)
	}
	if len(q) == 1 {
		return singular + " " + q[0]
	}
	return plural + " " + strings.Join(q, ", ")
}

// egress checks host, and the policies claiming it, against one Substrate
// EgressPolicy. A policy is checked only if it can select the actor the
// EgressPolicy belongs to, as far as that actor is known.
func (l *linter) egress(docs map[string]*policyfile.Document, host string, claims []policy.Claim, e EgressPolicy) {
	reach := e.Policy.Reach(host)
	if len(reach.Passthrough) == 0 && reach.Seen() {
		return
	}
	for _, c := range claims {
		var scope string
		switch {
		case e.Actor != nil:
			if !c.Selects(*e.Actor) {
				continue
			}
			scope = fmt.Sprintf(" for actor %s", e.Actor)
		case e.Policy.Atespace != "":
			if !selectsAtespace(c, e.Policy.Atespace) {
				continue
			}
			scope = fmt.Sprintf(" for the actor in atespace %s that the EgressPolicy belongs to", e.Policy.Atespace)
		default:
			scope = " for the actor the EgressPolicy belongs to"
		}
		d := docs[c.Policy]
		field := hostField(d, host) + ".host"
		if len(reach.Passthrough) > 0 {
			seen := append(slices.Clone(reach.HTTPS), reach.HTTP...)
			msg := fmt.Sprintf("%s forwards TLS to %s on %s without decrypting it (%s), so ate-gress never sees those requests and this policy is not enforced on them%s",
				e.File, host, ports(reach.Passthrough, len(seen) == 0), rules(reach.Passthrough), scope)
			if len(seen) > 0 {
				msg += fmt.Sprintf("; it is enforced only on %s (%s)", ports(seen, false), rules(seen))
			}
			l.add(TLSPassthrough, d, field, "%s", msg)
			continue
		}
		l.add(HostNotReached, d, field,
			"no http or https rule in %s reaches %s, so the gateway refuses that traffic before it calls ate-gress and this claim has no effect%s",
			e.File, host, scope)
	}
}

// selectsAtespace reports whether c selects some actor in atespace, which
// depends only on its atespace globs. path.Match reads a glob of [a-z0-9*-]
// as the policy compiler does.
func selectsAtespace(c policy.Claim, atespace string) bool {
	if c.Atespaces == nil {
		return true
	}
	return slices.ContainsFunc(c.Atespaces, func(g string) bool {
		ok, _ := path.Match(g, atespace)
		return ok
	})
}

// ports describes the ports of ms. exclusive is set when no other port of
// the host is decided differently, so that "every port" is the whole truth.
func ports(ms []egresspolicy.Match, exclusive bool) string {
	var numbers []string
	other := false
	for _, m := range ms {
		if m.Port == egresspolicy.OtherPorts {
			other = true
			continue
		}
		if n := fmt.Sprint(m.Port); !slices.Contains(numbers, n) {
			numbers = append(numbers, n)
		}
	}
	switch {
	case other && len(numbers) == 0 && exclusive:
		return "every port"
	case other && len(numbers) == 0:
		return "every other port"
	case other:
		return "ports " + strings.Join(numbers, ", ") + " and every other port"
	case len(numbers) == 1:
		return "port " + numbers[0]
	}
	return "ports " + strings.Join(numbers, ", ")
}

func rules(ms []egresspolicy.Match) string {
	var out []string
	for _, m := range ms {
		if s := fmt.Sprintf("%s %q", m.Rule.Field(), m.Pattern); !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return strings.Join(out, ", ")
}
