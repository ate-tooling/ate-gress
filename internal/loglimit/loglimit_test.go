package loglimit

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// allowed calls Allow n times at now and returns how many lines were allowed.
func allowed[K comparable](l *Limiter[K], key K, now time.Time, n int) int {
	var got int
	for range n {
		if ok, _, _ := l.Allow(key, now); ok {
			got++
		}
	}
	return got
}

func TestBurstThenRefill(t *testing.T) {
	l := New[string](2, 5, 16)
	if got := allowed(l, "a", t0, 100); got != 5 {
		t.Errorf("allowed at once = %d, want the burst of 5", got)
	}
	// Half a token is not a line.
	if got := allowed(l, "a", t0.Add(250*time.Millisecond), 1); got != 0 {
		t.Errorf("allowed after 250ms at 2/s = %d, want 0", got)
	}
	if got := allowed(l, "a", t0.Add(500*time.Millisecond), 10); got != 1 {
		t.Errorf("allowed after 500ms at 2/s = %d, want 1", got)
	}
	if got := allowed(l, "a", t0.Add(2*time.Second), 10); got != 3 {
		t.Errorf("allowed 1.5s later at 2/s = %d, want 3", got)
	}
	// A long quiet spell earns the burst back, and no more.
	if got := allowed(l, "a", t0.Add(time.Hour), 100); got != 5 {
		t.Errorf("allowed after an hour = %d, want the burst of 5", got)
	}
}

func TestSuppressedCount(t *testing.T) {
	l := New[string](1, 2, 16)
	for i := range 2 {
		if ok, n, shared := l.Allow("a", t0); !ok || n != 0 || shared {
			t.Fatalf("line %d = (%v, %d, %v), want allowed with nothing suppressed", i, ok, n, shared)
		}
	}
	for i := range 7 {
		if ok, n, _ := l.Allow("a", t0); ok || n != 0 {
			t.Fatalf("line %d past the burst = (%v, %d), want refused", i, ok, n)
		}
	}
	if ok, n, _ := l.Allow("a", t0.Add(time.Second)); !ok || n != 7 {
		t.Errorf("first line after suppression = (%v, %d), want allowed carrying 7", ok, n)
	}
	// The count was handed over; it is not reported twice.
	if ok, n, _ := l.Allow("a", t0.Add(2*time.Second)); !ok || n != 0 {
		t.Errorf("next line = (%v, %d), want allowed carrying 0", ok, n)
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := New[string](1, 3, 16)
	if got := allowed(l, "a", t0, 1000); got != 3 {
		t.Fatalf("a allowed = %d, want 3", got)
	}
	if ok, n, shared := l.Allow("b", t0); !ok || n != 0 || shared {
		t.Errorf("b's first line = (%v, %d, %v), want allowed: a's flood must not cost b", ok, n, shared)
	}
	if got := allowed(l, "b", t0, 10); got != 2 {
		t.Errorf("b allowed = %d more, want the rest of its own burst", got)
	}
	if ok, n, _ := l.Allow("a", t0.Add(time.Second)); !ok || n != 997 {
		t.Errorf("a's next line = (%v, %d), want allowed carrying only a's 997", ok, n)
	}
}

func TestClockGoingBackwards(t *testing.T) {
	l := New[string](1, 1, 16)
	if got := allowed(l, "a", t0, 2); got != 1 {
		t.Fatalf("allowed = %d, want 1", got)
	}
	if got := allowed(l, "a", t0.Add(-time.Hour), 5); got != 0 {
		t.Errorf("allowed with the clock an hour back = %d, want 0", got)
	}
	if got := allowed(l, "a", t0.Add(time.Second), 5); got != 1 {
		t.Errorf("allowed a second after the last refill = %d, want 1", got)
	}
}

// TestBound checks that the table never exceeds its cap, however many keys
// arrive, and that keys beyond it are limited together instead of each
// getting a burst.
func TestBound(t *testing.T) {
	const maxKeys, burst, total = 8, 2, 10_000
	l := New[int](1, burst, maxKeys)
	var lines, sharedLines int
	for k := range total {
		ok, _, shared := l.Allow(k, t0)
		if ok {
			lines++
		}
		if ok && shared {
			sharedLines++
		}
		if n := l.Len(); n > maxKeys {
			t.Fatalf("after %d keys the limiter tracks %d, want at most %d", k+1, n, maxKeys)
		}
	}
	if l.Len() != maxKeys {
		t.Errorf("tracked = %d, want %d", l.Len(), maxKeys)
	}
	if want := maxKeys + burst; lines != want || sharedLines != burst {
		t.Errorf("lines = %d (%d shared), want %d: one per tracked key and the shared burst of %d", lines, sharedLines, want, burst)
	}

	// The shared bucket reports what it refused, like any other. Keep the
	// tracked keys busy so that none can be forgotten for the new one.
	at := t0.Add(time.Second)
	for k := range maxKeys {
		l.Allow(k, at)
	}
	ok, n, shared := l.Allow(-1, at)
	if want := uint64(total - maxKeys - burst); !ok || !shared || n != want {
		t.Errorf("next untracked line = (%v, %d, %v), want allowed, shared, carrying %d", ok, n, shared, want)
	}
}

func TestEvictsOnlyQuietKeys(t *testing.T) {
	l := New[string](1, 2, 2)
	allowed(l, "old", t0, 5) // 2 lines, 3 suppressed
	allowed(l, "busy", t0.Add(time.Second), 2)

	// Both buckets are still draining: a third key may not displace either.
	if _, _, shared := l.Allow("new", t0.Add(time.Second)); !shared {
		t.Fatal("a key displaced a bucket that had not refilled")
	}

	// At 3s "old" has refilled, so it is forgotten for "new". "busy", used
	// more recently, stays.
	at := t0.Add(3 * time.Second)
	if ok, n, shared := l.Allow("new", at); !ok || n != 0 || shared {
		t.Fatalf("new key once the oldest was quiet = (%v, %d, %v), want its own bucket", ok, n, shared)
	}
	if l.Len() != 2 {
		t.Errorf("tracked = %d, want 2", l.Len())
	}
	if got := allowed(l, "busy", at, 5); got != 2 {
		t.Errorf("busy allowed = %d, want its refilled burst of 2 (it was not evicted)", got)
	}

	// The 3 lines "old" had suppressed and never reported are not lost: with
	// the table full of draining buckets again, the next shared line has them.
	if ok, n, shared := l.Allow("old", at); !ok || !shared || n != 3 {
		t.Errorf("shared line = (%v, %d, %v), want allowed, shared, carrying the 3 the evicted key held", ok, n, shared)
	}
}

func TestNewRejectsNonsense(t *testing.T) {
	for _, tt := range []struct {
		name           string
		rate           float64
		burst, maxKeys int
	}{
		{"zero rate", 0, 1, 1},
		{"negative rate", -1, 1, 1},
		{"zero burst", 1, 0, 1},
		{"zero keys", 1, 1, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("New did not panic")
				}
			}()
			New[string](tt.rate, tt.burst, tt.maxKeys)
		})
	}
}

// TestConcurrent hammers a small table from many goroutines with a frozen
// clock, so the totals are exact: every line is either allowed or counted as
// suppressed, and no key gets more than its burst.
func TestConcurrent(t *testing.T) {
	const (
		workers, perWorker = 16, 2000
		keys, burst        = 4, 10
	)
	l := New[int](1, burst, keys)
	var lines, reported atomic.Uint64
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			for i := range perWorker {
				ok, n, _ := l.Allow((w+i)%keys, t0)
				if ok {
					lines.Add(1)
					reported.Add(n)
				}
			}
		})
	}
	wg.Wait()
	if got, want := lines.Load(), uint64(keys*burst); got != want {
		t.Errorf("lines = %d, want %d", got, want)
	}
	// One more line per key collects what is still held.
	for k := range keys {
		ok, n, _ := l.Allow(k, t0.Add(time.Second))
		if !ok {
			t.Fatalf("key %d refused after a refill", k)
		}
		reported.Add(n)
	}
	if got, want := lines.Load()+reported.Load(), uint64(workers*perWorker); got != want {
		t.Errorf("lines + suppressed = %d, want every one of the %d calls accounted for", got, want)
	}
}

func BenchmarkAllow(b *testing.B) {
	l := New[int](1, 10, 4096)
	now := time.Now()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		var k int
		for pb.Next() {
			k++
			l.Allow(k%1024, now)
		}
	})
}
