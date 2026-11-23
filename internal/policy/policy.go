// Package policy compiles EgressRoutePolicy objects into an immutable Snapshot
// and decides requests against it.
//
// Everything security-relevant that ate-gress decides is decided here, by
// Snapshot.Decide, a pure function of the compiled policies and the request.
// The ext_proc server and the controller only translate in and out of it.
package policy

import (
	"strings"

	"github.com/ate-tooling/ate-gress/internal/identity"
	"github.com/ate-tooling/ate-gress/internal/pathmatch"
)

// Request is what Decide needs to know about an HTTP request.
type Request struct {
	Actor identity.Actor
	// Method is the :method pseudo-header.
	Method string
	// Authority is the :authority pseudo-header, which may carry a port.
	Authority string
	// Path is the :path pseudo-header, including any query.
	Path string
}

// Reason says why Decide reached its decision. The values are stable: they
// are metric labels, and the deny reasons are returned to the actor.
type Reason string

const (
	// ReasonUnclaimed allows a request to a host no policy selecting the actor
	// claims. Substrate's EgressPolicy has already allowed the host.
	ReasonUnclaimed Reason = "unclaimed"
	// ReasonRoute allows a request a route matched.
	ReasonRoute Reason = "route"
	// ReasonNoRoute denies a request to a claimed host that no route matched.
	ReasonNoRoute Reason = "no_route"
	// ReasonPath denies a request to a claimed host whose path Canonicalize
	// refused.
	ReasonPath Reason = "path"
	// ReasonAuthority denies a request whose :authority is not a hostname,
	// optionally with a port.
	ReasonAuthority Reason = "authority"

	// The ext_proc server denies for these reasons before it can call Decide.

	// ReasonIdentity denies a request without exactly one well-formed actor
	// identity attribute.
	ReasonIdentity Reason = "identity"
	// ReasonHeaders denies a request missing a pseudo-header or repeating one.
	ReasonHeaders Reason = "headers"
	// ReasonNotReady denies a request that arrives before the first snapshot.
	ReasonNotReady Reason = "not_ready"
)

// Decision is the outcome of Decide.
type Decision struct {
	Allowed bool
	Reason  Reason
	// Audited is set on an allowed request that Audit policies alone claimed
	// and that they would have denied for Reason.
	Audited bool
	// Policy names the policy that allowed the request, or, for a denied or
	// audited one, the first (by name) policy that claimed its host.
	Policy string
	// Pattern is the path template that allowed the request.
	Pattern string
	// LogAllowed is set on an allowed, unaudited request when a policy that
	// claims its host for its actor has LogAllowed, so the request is logged
	// as a denial would be. It is never set on a denied or audited request,
	// which are logged regardless.
	LogAllowed bool
}

// Decide applies s to r. It is safe for concurrent use and, for a request
// whose :authority is already lowercase, does not allocate.
func (s *Snapshot) Decide(r Request) Decision {
	host, ok := normalizeAuthority(r.Authority)
	if !ok {
		return Decision{Reason: ReasonAuthority}
	}

	var (
		path                     string
		pathErr                  error
		pathChecked              bool
		enforcing, auditing      bool
		firstClaim               string
		auditMatch, auditPattern string
	)
	hps := s.hosts[host]
	for _, hp := range hps {
		if !hp.selector.matches(r.Actor) {
			continue
		}
		if firstClaim == "" {
			firstClaim = hp.policy
		}
		if hp.mode == modeEnforce {
			enforcing = true
		} else {
			auditing = true
		}
		if !pathChecked {
			path, pathErr = pathmatch.Canonicalize(r.Path)
			pathChecked = true
		}
		if pathErr != nil {
			continue
		}
		pattern, matched := hp.match(r.Method, path)
		switch {
		case !matched:
		case hp.mode == modeEnforce:
			return Decision{
				Allowed: true, Reason: ReasonRoute, Policy: hp.policy, Pattern: pattern,
				LogAllowed: s.logAllowed(host, hps, r.Actor),
			}
		case auditMatch == "":
			auditMatch, auditPattern = hp.policy, pattern
		}
	}

	switch {
	case !enforcing && !auditing:
		return Decision{Allowed: true, Reason: ReasonUnclaimed}
	case !enforcing && auditMatch != "":
		return Decision{Allowed: true, Reason: ReasonRoute, Policy: auditMatch, Pattern: auditPattern, LogAllowed: s.logAllowed(host, hps, r.Actor)}
	}
	reason := ReasonNoRoute
	if pathErr != nil {
		reason = ReasonPath
	}
	return Decision{Allowed: !enforcing, Audited: !enforcing, Reason: reason, Policy: firstClaim}
}

// logAllowed reports whether a policy in hps, the policies claiming host,
// selects a and has LogAllowed. Decide calls it only for an allowed request,
// and the scan is skipped for a host no policy with LogAllowed claims.
func (s *Snapshot) logAllowed(host string, hps []*hostPolicy, a identity.Actor) bool {
	if !s.logHosts[host] {
		return false
	}
	for _, hp := range hps {
		if hp.logAllowed && hp.selector.matches(a) {
			return true
		}
	}
	return false
}

// normalizeAuthority returns the lowercase host part of authority, without a
// port or a trailing dot. It refuses anything else that is not a hostname or
// IP literal, such as userinfo, so a policy's host cannot be sidestepped by
// spelling it differently.
func normalizeAuthority(authority string) (string, bool) {
	host := authority
	if strings.HasPrefix(host, "[") {
		end := strings.IndexByte(host, ']')
		if end < 0 || !validPort(host[end+1:]) || !validIPv6Body(host[1:end]) {
			return "", false
		}
		return strings.ToLower(host[:end+1]), true
	}
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		if !validPort(host[i:]) {
			return "", false
		}
		host = host[:i]
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return "", false
	}
	lower := true
	for i := 0; i < len(host); i++ {
		switch c := host[i]; {
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '.':
		case 'A' <= c && c <= 'Z':
			lower = false
		default:
			return "", false
		}
	}
	// One trailing dot (the root label) was trimmed above; any other empty
	// label makes the name invalid.
	if strings.Contains(host, "..") || host[0] == '.' || host[len(host)-1] == '.' {
		return "", false
	}
	if !lower {
		host = strings.ToLower(host)
	}
	return host, true
}

// validPort reports whether s is empty or ":" followed by 1-5 digits.
func validPort(s string) bool {
	if s == "" {
		return true
	}
	if s[0] != ':' || len(s) < 2 || len(s) > 6 {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func validIPv6Body(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case '0' <= c && c <= '9', 'a' <= c && c <= 'f', 'A' <= c && c <= 'F', c == ':', c == '.':
		default:
			return false
		}
	}
	return true
}
