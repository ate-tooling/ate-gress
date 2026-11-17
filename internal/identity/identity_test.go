package identity

import (
	"errors"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	p, err := NewParser(DefaultTrustDomain)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		id   string
		want Actor
		ok   bool
	}{
		{name: "valid", id: "spiffe://substrate-actor.local/worker-for-actor/research/agent-1", want: Actor{"research", "agent-1"}, ok: true},
		{name: "max-length label", id: "spiffe://substrate-actor.local/worker-for-actor/a/" + strings.Repeat("b", 63), want: Actor{"a", strings.Repeat("b", 63)}, ok: true},

		{name: "empty", id: ""},
		{name: "actor SPIFFE ID, not the worker-for-actor one", id: "spiffe://substrate-actor.local/actor/research/agent-1"},
		{name: "other trust domain", id: "spiffe://evil.local/worker-for-actor/research/agent-1"},
		{name: "trust domain suffix", id: "spiffe://substrate-actor.local.evil/worker-for-actor/research/agent-1"},
		{name: "port", id: "spiffe://substrate-actor.local:443/worker-for-actor/research/agent-1"},
		{name: "userinfo", id: "spiffe://x@substrate-actor.local/worker-for-actor/research/agent-1"},
		{name: "scheme case", id: "SPIFFE://substrate-actor.local/worker-for-actor/research/agent-1"},
		{name: "missing name", id: "spiffe://substrate-actor.local/worker-for-actor/research"},
		{name: "empty name", id: "spiffe://substrate-actor.local/worker-for-actor/research/"},
		{name: "empty atespace", id: "spiffe://substrate-actor.local/worker-for-actor//agent-1"},
		{name: "extra segment", id: "spiffe://substrate-actor.local/worker-for-actor/research/agent-1/x"},
		{name: "query", id: "spiffe://substrate-actor.local/worker-for-actor/research/agent-1?x"},
		{name: "fragment", id: "spiffe://substrate-actor.local/worker-for-actor/research/agent-1#x"},
		{name: "escaped slash", id: "spiffe://substrate-actor.local/worker-for-actor/research%2Fagent-1"},
		{name: "uppercase", id: "spiffe://substrate-actor.local/worker-for-actor/Research/agent-1"},
		{name: "leading hyphen", id: "spiffe://substrate-actor.local/worker-for-actor/-research/agent-1"},
		{name: "trailing hyphen", id: "spiffe://substrate-actor.local/worker-for-actor/research/agent-"},
		{name: "dot", id: "spiffe://substrate-actor.local/worker-for-actor/research/agent.1"},
		{name: "label too long", id: "spiffe://substrate-actor.local/worker-for-actor/a/" + strings.Repeat("b", 64)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := p.Parse(tt.id)
			if !tt.ok {
				if !errors.Is(err, ErrMalformed) {
					t.Fatalf("Parse(%q) = %v, %v; want ErrMalformed", tt.id, got, err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("Parse(%q) = %v, %v; want %v", tt.id, got, err, tt.want)
			}
		})
	}
}

func TestNewParserRejectsBadTrustDomain(t *testing.T) {
	for _, td := range []string{"", "a..b", "a/b", "A.local", "-a.local", "a.local."} {
		if _, err := NewParser(td); err == nil {
			t.Errorf("NewParser(%q) succeeded, want an error", td)
		}
	}
}

func TestParseDoesNotAllocate(t *testing.T) {
	p, err := NewParser(DefaultTrustDomain)
	if err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(100, func() {
		if _, err := p.Parse("spiffe://substrate-actor.local/worker-for-actor/research/agent-1"); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Errorf("Parse allocated %v times per call, want 0", allocs)
	}
}

func FuzzParse(f *testing.F) {
	f.Add("spiffe://substrate-actor.local/worker-for-actor/research/agent-1")
	f.Add("spiffe://substrate-actor.local/worker-for-actor/a/b/c")
	p, err := NewParser(DefaultTrustDomain)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, id string) {
		a, err := p.Parse(id)
		if err != nil {
			return
		}
		if want := "spiffe://substrate-actor.local/worker-for-actor/" + a.String(); id != want {
			t.Fatalf("Parse(%q) = %v, which does not round-trip (%q)", id, a, want)
		}
	})
}
