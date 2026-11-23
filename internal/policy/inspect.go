package policy

import (
	"maps"
	"slices"

	"github.com/ate-tooling/ate-gress/internal/identity"
)

// Claim is one policy's claim on one host, as the Snapshot holds it. It is a
// read-only view for tools that explain or lint a policy set; Decide does not
// use it.
type Claim struct {
	// Policy is the name of the claiming policy.
	Policy string
	// Audit is set for an Audit policy and clear for an Enforce one.
	Audit bool
	// Rejected is set for a policy that did not compile. It claims the host
	// with no routes, so it allows nothing, and its mode and selector are
	// the ones rejectedClaims reads from what was written: Enforce unless
	// the policy says Audit, and a selector list with a glob that does not
	// compile selecting everything.
	Rejected bool
	// LogAllowed is the policy's logAllowed.
	LogAllowed bool
	// Atespaces and Names are the selector's globs, as written. A nil list
	// matches everything.
	Atespaces, Names []string

	selector selector
}

// Selects reports whether the claiming policy selects a. It is the same test
// Decide applies.
func (c Claim) Selects(a identity.Actor) bool { return c.selector.matches(a) }

// Hosts returns the hosts some policy in s claims, sorted.
func (s *Snapshot) Hosts() []string {
	return slices.Sorted(maps.Keys(s.hosts))
}

// Claims returns the claims on host, which must be in the lowercase form
// policies spell hosts in, in the order Decide considers them.
func (s *Snapshot) Claims(host string) []Claim {
	hps := s.hosts[host]
	if len(hps) == 0 {
		return nil
	}
	out := make([]Claim, len(hps))
	for i, hp := range hps {
		out[i] = Claim{
			Policy:     hp.policy,
			Audit:      hp.mode == modeAudit,
			Rejected:   hp.rejected,
			LogAllowed: hp.logAllowed,
			Atespaces:  patterns(hp.selector.atespaces),
			Names:      patterns(hp.selector.names),
			selector:   hp.selector,
		}
	}
	return out
}

// ClaimsFor returns the claims on the host authority names, by the policies
// that select a: the policies Decide consults for a request from a to
// authority. The host is the normalized one, and ok is false for an authority
// Decide refuses.
func (s *Snapshot) ClaimsFor(authority string, a identity.Actor) (host string, claims []Claim, ok bool) {
	host, ok = normalizeAuthority(authority)
	if !ok {
		return "", nil, false
	}
	for _, c := range s.Claims(host) {
		if c.Selects(a) {
			claims = append(claims, c)
		}
	}
	return host, claims, true
}

func patterns(globs []glob) []string {
	if globs == nil {
		return nil
	}
	out := make([]string, len(globs))
	for i, g := range globs {
		out[i] = g.pattern
	}
	return out
}
