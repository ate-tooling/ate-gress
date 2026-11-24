package policy

import (
	"slices"
	"sync"
	"sync/atomic"
)

// Store holds the snapshot in effect. The controller replaces it; every
// request reads it. Reads never block.
type Store struct {
	current    atomic.Pointer[Live]
	generation atomic.Uint64
	// swapping serializes Swap, which reads the tallies in effect to carry
	// them over. Readers do not take it.
	swapping sync.Mutex
}

// Live is a snapshot in effect together with the tallies of its policies.
// The tallies are kept beside the snapshot, not in it, so the snapshot stays
// immutable and Snapshot.Decide pure.
type Live struct {
	snap *Snapshot
	// tallies is indexed as snap.policies is.
	tallies []*Tally
}

// Decide is Snapshot.Decide, and counts the decision against the policies it
// is attributed to, as Tally describes. It does not allocate or lock.
func (l *Live) Decide(r Request) Decision {
	var a attribution
	d := l.snap.decide(r, &a)
	a.count(l.tallies)
	return d
}

// Load returns the snapshot in effect, or nil before the first Swap.
func (s *Store) Load() *Snapshot {
	if l := s.current.Load(); l != nil {
		return l.snap
	}
	return nil
}

// Live returns the snapshot in effect with its tallies, or nil before the
// first Swap.
func (s *Store) Live() *Live { return s.current.Load() }

// Swap puts snap in effect and returns its generation, which counts swaps
// from 1.
//
// A policy that was in the previous snapshot keeps its tally; one that is
// new starts from zero, and the tally of one that is gone is dropped. A
// request still deciding on the previous snapshot counts into the previous
// tallies: for a policy that stays that is the same tally, and for one that
// is gone the count is lost with it, which is the point of dropping it.
func (s *Store) Swap(snap *Snapshot) uint64 {
	s.swapping.Lock()
	defer s.swapping.Unlock()
	next := &Live{snap: snap, tallies: make([]*Tally, len(snap.policies))}
	prev := s.current.Load()
	for i, name := range snap.policies {
		if prev != nil {
			if j, ok := slices.BinarySearch(prev.snap.policies, name); ok {
				next.tallies[i] = prev.tallies[j]
				continue
			}
		}
		next.tallies[i] = new(Tally)
	}
	gen := s.generation.Add(1)
	s.current.Store(next)
	return gen
}

// Ready reports whether a snapshot has been put in effect.
func (s *Store) Ready() bool { return s.current.Load() != nil }

// PolicyCounts returns the tally of every policy in the snapshot in effect,
// sorted by policy name.
func (s *Store) PolicyCounts() []PolicyCounts {
	l := s.current.Load()
	if l == nil {
		return nil
	}
	counts := make([]PolicyCounts, len(l.tallies))
	for i, t := range l.tallies {
		counts[i] = PolicyCounts{
			Policy: l.snap.policies[i],
			Allow:  t.allow.Load(), Deny: t.deny.Load(), Audit: t.audit.Load(),
		}
	}
	return counts
}
