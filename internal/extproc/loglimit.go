package extproc

import (
	"github.com/ate-tooling/ate-gress/internal/identity"
	"github.com/ate-tooling/ate-gress/internal/loglimit"
	"github.com/ate-tooling/ate-gress/internal/policy"
)

// maxLogKeys caps the keys the decision log limiter tracks, and so its
// memory: a few hundred bytes a key, around a megabyte in all. Keys beyond
// the cap are limited together; see loglimit.Limiter.
const maxLogKeys = 4096

// logKey is what denial and audit logs are rate-limited by: one actor
// repeating one kind of denial. The actor decides how often it sends
// requests, so every field must be something it cannot vary freely. The
// path and the authority are deliberately absent: an actor that could pick
// part of the key would get a fresh burst with every new value.
type logKey struct {
	audit  bool
	reason policy.Reason
	// policy is the first policy that claimed the host. An actor reaches as
	// many values as there are policies selecting it, which the cluster's
	// operator bounds.
	policy string
	// actor is the parsed identity, which the gateway authenticated. It is
	// zero for a request denied before one was parsed (reasons headers and
	// identity). The identity string of such a request is unverified input,
	// so those denials share one key per reason, whoever sent them.
	actor identity.Actor
}

func newLogKey(pr parsedRequest, d policy.Decision) logKey {
	return logKey{audit: d.Audited, reason: d.Reason, policy: d.Policy, actor: pr.Actor}
}

// LimitDecisionLogs rate-limits the Info records of denials and audits: each
// actor, for each reason and policy, gets burst lines and then rate lines
// per second. A rate of zero leaves them unlimited, which is the default.
// Call it before the Server handles requests.
//
// The allowed requests of logAllowed policies are never limited, and a
// logger at Debug still records every decision.
func (s *Server) LimitDecisionLogs(rate float64, burst int) {
	if rate == 0 {
		s.limiter = nil
		return
	}
	s.limiter = loglimit.New[logKey](rate, burst, maxLogKeys)
}
