// Package loglimit bounds how often a log line is written for a key, for
// logs whose volume a caller controls.
//
// Each key has a token bucket: a burst of lines, then a steady rate. A line
// that finds its bucket empty is counted, not written, and the count is
// handed to the next line that is written for the key, so the record of how
// much happened survives the suppression.
package loglimit

import (
	"math"
	"sync"
	"time"
)

// Limiter is a set of token buckets, one per key, holding at most a fixed
// number of keys. It is safe for concurrent use.
//
// The key type must be built from bounded values. A key that a caller can
// vary freely gets a fresh burst each time, and limits nothing.
type Limiter[K comparable] struct {
	rate  float64 // tokens per second
	burst float64
	max   int

	// One mutex, not shards: the critical section is a map lookup and some
	// arithmetic, and the caller only reaches it for a line it would
	// otherwise serialize on the log handler's own lock to write.
	mu      sync.Mutex
	entries map[K]*entry[K]
	// lru is the sentinel of a ring ordered by last use: lru.next is the most
	// recently used entry and lru.prev the least.
	lru entry[K]
	// shared serves the keys that do not fit. Evicting a bucket that is still
	// draining to make room would hand its key a fresh burst, so more than
	// max busy keys could log without limit by displacing each other; they
	// share one bucket instead, which keeps the total rate bounded.
	shared bucket
}

type bucket struct {
	tokens     float64
	last       time.Time
	suppressed uint64
}

type entry[K comparable] struct {
	bucket
	key        K
	prev, next *entry[K]
}

// New returns a Limiter that allows each key burst lines and then rate lines
// per second, and tracks at most maxKeys keys. rate must be positive and
// finite, and burst and maxKeys at least 1.
func New[K comparable](rate float64, burst, maxKeys int) *Limiter[K] {
	if !(rate > 0) || math.IsInf(rate, 0) || burst < 1 || maxKeys < 1 {
		panic("loglimit: rate, burst and maxKeys must be positive, and rate finite")
	}
	l := &Limiter[K]{
		rate:    rate,
		burst:   float64(burst),
		max:     maxKeys,
		entries: make(map[K]*entry[K]),
		shared:  bucket{tokens: float64(burst)},
	}
	l.lru.prev, l.lru.next = &l.lru, &l.lru
	return l
}

// Allow reports whether a line for key may be written at now. If it may,
// suppressed is how many lines were refused since the last one allowed.
//
// The first line for a key is always allowed, with one exception: when the
// Limiter already tracks maxKeys keys and none of them has been quiet long
// enough to forget, the line is charged to a bucket shared by all such keys.
// shared reports that, and suppressed then counts lines of any key: those
// refused by the shared bucket, and those refused for a key that was
// forgotten before another of its lines could report them.
func (l *Limiter[K]) Allow(key K, now time.Time) (ok bool, suppressed uint64, shared bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e := l.entries[key]
	switch {
	case e != nil:
		e.unlink()
	case len(l.entries) < l.max:
		e = &entry[K]{key: key}
		e.bucket = bucket{tokens: l.burst, last: now}
		l.entries[key] = e
	default:
		oldest := l.lru.prev
		if !oldest.full(now, l.rate, l.burst) {
			ok, suppressed = l.shared.take(now, l.rate, l.burst)
			return ok, suppressed, true
		}
		// A full bucket is indistinguishable from a new one, so forgetting it
		// costs nothing but a count it was still holding.
		l.shared.suppressed += oldest.suppressed
		delete(l.entries, oldest.key)
		oldest.unlink()
		e = oldest
		e.key = key
		e.bucket = bucket{tokens: l.burst, last: now}
		l.entries[key] = e
	}
	e.prev, e.next = &l.lru, l.lru.next
	e.prev.next, e.next.prev = e, e

	ok, suppressed = e.take(now, l.rate, l.burst)
	return ok, suppressed, false
}

// Len returns the number of keys tracked.
func (l *Limiter[K]) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

func (e *entry[K]) unlink() {
	e.prev.next, e.next.prev = e.next, e.prev
}

// refill adds the tokens earned since the bucket was last used. A clock that
// did not advance, or went backwards, earns nothing.
func (b *bucket) refill(now time.Time, rate, burst float64) {
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = min(burst, b.tokens+elapsed.Seconds()*rate)
		b.last = now
	}
}

func (b *bucket) take(now time.Time, rate, burst float64) (bool, uint64) {
	b.refill(now, rate, burst)
	if b.tokens < 1 {
		b.suppressed++
		return false, 0
	}
	b.tokens--
	n := b.suppressed
	b.suppressed = 0
	return true, n
}

// full reports whether the bucket would hold its whole burst at now.
func (b *bucket) full(now time.Time, rate, burst float64) bool {
	return b.tokens+now.Sub(b.last).Seconds()*rate >= burst
}
