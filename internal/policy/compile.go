package policy

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/ate-tooling/ate-gress/api/v1alpha1"
	"github.com/ate-tooling/ate-gress/internal/identity"
	"github.com/ate-tooling/ate-gress/internal/pathmatch"
)

// Snapshot is a compiled, immutable set of policies.
type Snapshot struct {
	// hosts maps a lowercase host to the policies that claim it, sorted by
	// policy name so decisions are deterministic.
	hosts map[string][]*hostPolicy
	// logHosts holds the hosts claimed by at least one policy with
	// LogAllowed, so Decide can skip looking for one everywhere else.
	logHosts map[string]bool
	// policies names every policy the snapshot was compiled from, rejected
	// ones too, sorted. A hostPolicy's index points into it, and so do the
	// tallies a Store keeps beside the snapshot.
	policies []string
}

type mode uint8

const (
	modeEnforce mode = iota
	modeAudit
)

type hostPolicy struct {
	policy string
	// index is the policy's place in Snapshot.policies.
	index int
	mode  mode
	// rejected is set if the policy did not compile. It then has no routes,
	// and claims what rejectedClaims says.
	rejected   bool
	logAllowed bool
	selector   selector
	routes     []route
}

type route struct {
	methods methodSet
	paths   []*pathmatch.Template
}

func (hp *hostPolicy) match(method, path string) (string, bool) {
	m, ok := parseMethod(method)
	if !ok {
		return "", false
	}
	for i := range hp.routes {
		r := &hp.routes[i]
		if r.methods&m == 0 {
			continue
		}
		for _, t := range r.paths {
			if t.Match(path) {
				return t.String(), true
			}
		}
	}
	return "", false
}

// Result is the outcome of compiling one policy.
type Result struct {
	Name       string
	Generation int64
	// Err is nil if the policy is in effect as written, and otherwise says
	// why it was rejected.
	Err error
	// Effect says, for a rejected policy, what it does while it is rejected.
	Effect string
}

// Compile compiles policies into a Snapshot. A policy that does not compile is
// rejected: its Result carries the error, it allows nothing, and it still
// claims its hosts, as rejectedClaims describes. Leaving it out would instead
// release every host that it alone claimed, and turn denials into allows.
// Results are in the order of policies.
func Compile(policies []v1alpha1.EgressRoutePolicy) (*Snapshot, []Result) {
	s := &Snapshot{hosts: make(map[string][]*hostPolicy), logHosts: make(map[string]bool)}
	results := make([]Result, len(policies))
	for i := range policies {
		p := &policies[i]
		results[i] = Result{Name: p.Name, Generation: p.Generation}
		hps, err := compilePolicy(p)
		if err != nil {
			results[i].Err = err
			hps, results[i].Effect = rejectedClaims(p)
		}
		s.policies = append(s.policies, p.Name)
		for host, hp := range hps {
			s.hosts[host] = append(s.hosts[host], hp)
			if hp.logAllowed {
				s.logHosts[host] = true
			}
		}
	}
	slices.Sort(s.policies)
	s.policies = slices.Compact(s.policies)
	for _, hps := range s.hosts {
		slices.SortFunc(hps, func(a, b *hostPolicy) int { return strings.Compare(a.policy, b.policy) })
		for _, hp := range hps {
			hp.index, _ = slices.BinarySearch(s.policies, hp.policy)
		}
	}
	return s, results
}

var hostRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// compilePolicy re-checks everything the CRD schema checks: the schema can be
// bypassed by an older CRD, and the compiler is what the decision relies on.
func compilePolicy(p *v1alpha1.EgressRoutePolicy) (map[string]*hostPolicy, error) {
	var m mode
	switch p.Spec.EnforcementMode {
	case v1alpha1.EnforcementModeEnforce, "":
		m = modeEnforce
	case v1alpha1.EnforcementModeAudit:
		m = modeAudit
	default:
		return nil, fmt.Errorf("enforcementMode %q is not Enforce or Audit", p.Spec.EnforcementMode)
	}
	sel, err := compileSelector(p.Spec.ActorSelector)
	if err != nil {
		return nil, fmt.Errorf("actorSelector: %w", err)
	}
	if len(p.Spec.Hosts) == 0 {
		return nil, errors.New("hosts: at least one host is required")
	}

	out := make(map[string]*hostPolicy, len(p.Spec.Hosts))
	for i, h := range p.Spec.Hosts {
		if len(h.Host) > 253 || !hostRE.MatchString(h.Host) {
			return nil, fmt.Errorf("hosts[%d]: %q is not a lowercase hostname", i, h.Host)
		}
		if _, dup := out[h.Host]; dup {
			return nil, fmt.Errorf("hosts[%d]: %q is listed twice", i, h.Host)
		}
		hp := &hostPolicy{policy: p.Name, mode: m, logAllowed: p.Spec.LogAllowed, selector: sel, routes: make([]route, 0, len(h.Routes))}
		for j, r := range h.Routes {
			cr, err := compileRoute(r)
			if err != nil {
				return nil, fmt.Errorf("hosts[%d].routes[%d]: %w", i, j, err)
			}
			hp.routes = append(hp.routes, cr)
		}
		out[h.Host] = hp
	}
	return out, nil
}

// rejectedClaims is what a policy that did not compile claims, and a sentence
// or two saying so for its status. The policy keeps its hosts, for its actors,
// with no routes: it is the lockdown of everything it lists.
//
// Whatever part of it cannot be understood is read the way that denies more:
//
//   - No route is kept, not even one that compiles, so that a rejected policy
//     allows nothing rather than some part of what was written.
//   - A mode that is not Audit is Enforce. A mode this version does not know
//     may deny, and a misspelled Enforce certainly was meant to.
//   - A selector list holding a glob that does not compile selects everything,
//     since the glob may have been meant to select anyone. The other list
//     still narrows the selector: an actor is selected only when both lists
//     match, whatever the glob meant.
//   - A host is claimed under the name a request for it is looked up by, so
//     "Example.com" and "example.com:443" claim example.com. A host that no
//     :authority normalizes to, such as "*.example.com", names nothing Decide
//     could look up, and is not claimed.
func rejectedClaims(p *v1alpha1.EgressRoutePolicy) (map[string]*hostPolicy, string) {
	var effect strings.Builder
	m := modeEnforce
	switch p.Spec.EnforcementMode {
	case v1alpha1.EnforcementModeAudit:
		m = modeAudit
	case v1alpha1.EnforcementModeEnforce, "":
	default:
		effect.WriteString(" Its enforcementMode is read as Enforce.")
	}
	var sel selector
	var err error
	if sel.atespaces, err = compileGlobs(p.Spec.ActorSelector.Atespaces); err != nil {
		sel.atespaces = nil
		effect.WriteString(" Its actorSelector.atespaces is read as selecting every atespace.")
	}
	if sel.names, err = compileGlobs(p.Spec.ActorSelector.Names); err != nil {
		sel.names = nil
		effect.WriteString(" Its actorSelector.names is read as selecting every name.")
	}
	out := make(map[string]*hostPolicy, len(p.Spec.Hosts))
	unclaimed := 0
	for _, h := range p.Spec.Hosts {
		host, ok := normalizeAuthority(h.Host)
		if !ok {
			unclaimed++
			continue
		}
		out[host] = &hostPolicy{policy: p.Name, mode: m, rejected: true, logAllowed: p.Spec.LogAllowed, selector: sel}
	}
	if unclaimed > 0 {
		fmt.Fprintf(&effect, " %d of its %d hosts cannot be claimed, because no request could name them.", unclaimed, len(p.Spec.Hosts))
	}
	switch {
	case len(out) == 0:
		return out, "The policy allows nothing and claims no host, so it has no effect."
	case m == modeAudit:
		return out, "The policy allows nothing and still claims its hosts. It is an Audit policy, so it denies nothing: " +
			"requests to them from the actors it selects are audited unless another policy decides them." + effect.String()
	}
	return out, "The policy allows nothing and still claims its hosts: " +
		"requests to them from the actors it selects are denied unless another Enforce policy allows them." + effect.String()
}

func compileRoute(r v1alpha1.Route) (route, error) {
	var cr route
	if len(r.Methods) == 0 {
		return route{}, errors.New("methods: at least one method is required")
	}
	for _, m := range r.Methods {
		bit, ok := parseMethod(string(m))
		if !ok {
			return route{}, fmt.Errorf("methods: %q is not a supported method", m)
		}
		cr.methods |= bit
	}
	if len(r.Paths) == 0 {
		return route{}, errors.New("paths: at least one path is required")
	}
	for _, p := range r.Paths {
		t, err := pathmatch.Compile(p, r.CaseInsensitive)
		if err != nil {
			return route{}, fmt.Errorf("paths: %w", err)
		}
		cr.paths = append(cr.paths, t)
	}
	return cr, nil
}

type methodSet uint8

const (
	methodGet methodSet = 1 << iota
	methodHead
	methodPost
	methodPut
	methodPatch
	methodDelete
	methodOptions
)

// parseMethod maps a method to its bit. HTTP methods are case-sensitive, so
// "get" is not GET.
func parseMethod(m string) (methodSet, bool) {
	switch m {
	case "GET":
		return methodGet, true
	case "HEAD":
		return methodHead, true
	case "POST":
		return methodPost, true
	case "PUT":
		return methodPut, true
	case "PATCH":
		return methodPatch, true
	case "DELETE":
		return methodDelete, true
	case "OPTIONS":
		return methodOptions, true
	}
	return 0, false
}

// selector matches actors against atespace and name globs. A nil glob list
// matches everything.
type selector struct {
	atespaces, names []glob
}

func (s selector) matches(a identity.Actor) bool {
	return matchAny(s.atespaces, a.Atespace) && matchAny(s.names, a.Name)
}

func matchAny(globs []glob, s string) bool {
	if globs == nil {
		return true
	}
	for _, g := range globs {
		if g.match(s) {
			return true
		}
	}
	return false
}

// glob is a pattern in which "*" matches any run of characters.
type glob struct {
	pattern string
	literal bool
}

func (g glob) match(s string) bool {
	if g.literal {
		return s == g.pattern
	}
	// The pattern holds only [a-z0-9*-], so path.Match treats it as "*"
	// wildcards and literals, and it cannot return ErrBadPattern.
	ok, _ := path.Match(g.pattern, s)
	return ok
}

var globRE = regexp.MustCompile(`^[a-z0-9*-]{1,63}$`)

func compileSelector(s v1alpha1.ActorSelector) (selector, error) {
	atespaces, err := compileGlobs(s.Atespaces)
	if err != nil {
		return selector{}, fmt.Errorf("atespaces: %w", err)
	}
	names, err := compileGlobs(s.Names)
	if err != nil {
		return selector{}, fmt.Errorf("names: %w", err)
	}
	return selector{atespaces: atespaces, names: names}, nil
}

func compileGlobs(patterns []string) ([]glob, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	globs := make([]glob, 0, len(patterns))
	for _, p := range patterns {
		if !globRE.MatchString(p) {
			return nil, fmt.Errorf("%q is not a glob of [a-z0-9*-]", p)
		}
		globs = append(globs, glob{pattern: p, literal: !strings.Contains(p, "*")})
	}
	return globs, nil
}
