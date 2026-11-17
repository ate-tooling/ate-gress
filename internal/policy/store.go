package policy

import "sync/atomic"

// Store holds the snapshot in effect. The controller replaces it; every
// request reads it. Reads never block.
type Store struct {
	current    atomic.Pointer[Snapshot]
	generation atomic.Uint64
}

// Load returns the snapshot in effect, or nil before the first Swap.
func (s *Store) Load() *Snapshot { return s.current.Load() }

// Swap puts snap in effect and returns its generation, which counts swaps
// from 1.
func (s *Store) Swap(snap *Snapshot) uint64 {
	gen := s.generation.Add(1)
	s.current.Store(snap)
	return gen
}

// Ready reports whether a snapshot has been put in effect.
func (s *Store) Ready() bool { return s.current.Load() != nil }
