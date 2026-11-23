package policy

import (
	"sync/atomic"

	"github.com/ate-tooling/ate-gress/internal/identity"
)

// Tally counts the requests attributed to one policy. A Store keeps one per
// policy in the snapshot in effect and carries it over from snapshot to
// snapshot for as long as the policy stays.
//
// The attribution is what an operator needs in order to act on one policy,
// which is not always the policy Decision.Policy names:
//
//   - allow: the policy's route allowed the request. This is
//     Decision.Policy, the first policy by name whose route counted.
//   - deny: the request was denied and the policy is an Enforce policy that
//     claimed its host for its actor. A denial is the joint verdict of every
//     such policy, so each of them counts it.
//   - audit: the policy is an Audit policy that claimed the request's host
//     for its actor and has no route for it, and no Enforce policy claimed
//     it. The request was allowed; it would have been denied had this policy
//     alone been switched to Enforce.
//
// One request can therefore count against several policies, and audit counts
// requests Decision.Audited does not: a request another Audit policy's route
// allowed is not audited, yet enforcing this policy would deny it.
//
// A rejected policy has a tally like any other, and is counted as the
// lockdown it is read as: never allow, and deny or audit for every request
// to a host it claims for the actor. Its deny count is how to see what a
// rejected policy is costing, including where an accepted policy claims the
// host as well and the decision's reason does not show it.
type Tally struct {
	allow, deny, audit atomic.Uint64
}

// PolicyCounts is a policy's tally at one moment.
type PolicyCounts struct {
	Policy             string
	Allow, Deny, Audit uint64
}

// attributionBits is how many of a host's policies decide notes in a bit set.
// The count recomputes the rest, so that a host many policies claim costs the
// common case nothing.
const attributionBits = 64

// attribution is what decide notes about one decision for count: either the
// Enforce policy that allowed it, or the policies claiming its host and what
// is needed to tell which of them claimed and matched the request.
type attribution struct {
	allowedBy *hostPolicy

	claimants []*hostPolicy
	// enforcing is set if an Enforce policy claimed the request, which was
	// therefore denied; otherwise Audit policies alone claimed it.
	enforcing bool
	// Bit i of claimBits is set if claimants[i] selects the actor, and of
	// matchBits if it also has a route for the request.
	claimBits, matchBits uint64
	// The rest is for the claimants past attributionBits.
	actor        identity.Actor
	method, path string
	pathOK       bool
}

func (a *attribution) claimed(i int) bool {
	if i < attributionBits {
		return a.claimBits>>i&1 != 0
	}
	return a.claimants[i].selector.matches(a.actor)
}

func (a *attribution) matched(i int) bool {
	if i < attributionBits {
		return a.matchBits>>i&1 != 0
	}
	if !a.pathOK {
		return false
	}
	_, ok := a.claimants[i].match(a.method, a.path)
	return ok
}

// count adds the decision to the tallies of the policies it is attributed to.
// tallies is indexed as Snapshot.policies is.
func (a *attribution) count(tallies []*Tally) {
	if a.allowedBy != nil {
		tallies[a.allowedBy.index].allow.Add(1)
		return
	}
	allowed := false
	for i, hp := range a.claimants {
		switch {
		case a.enforcing:
			if hp.mode == modeEnforce && a.claimed(i) {
				tallies[hp.index].deny.Add(1)
			}
		case !a.claimed(i):
		case !a.matched(i):
			tallies[hp.index].audit.Add(1)
		case !allowed:
			// The first Audit policy with a route for the request is the one
			// Decide names as allowing it.
			tallies[hp.index].allow.Add(1)
			allowed = true
		}
	}
}
