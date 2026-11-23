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
}

type mode uint8

const (
	modeEnforce mode = iota
	modeAudit
)

type hostPolicy struct {
	policy     string
	mode       mode
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
	// Err is nil if the policy is in the snapshot, and otherwise says why it
	// was left out.
	Err error
}

// Compile compiles policies into a Snapshot. A policy that does not compile is
// left out, which can only remove allows, and its Result carries the error.
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
			continue
		}
		for host, hp := range hps {
			s.hosts[host] = append(s.hosts[host], hp)
			if hp.logAllowed {
				s.logHosts[host] = true
			}
		}
	}
	for _, hps := range s.hosts {
		slices.SortFunc(hps, func(a, b *hostPolicy) int { return strings.Compare(a.policy, b.policy) })
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
