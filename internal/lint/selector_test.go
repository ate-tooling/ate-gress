package lint

import (
	"fmt"
	"testing"

	"github.com/ate-tooling/ate-gress/internal/identity"
	"github.com/ate-tooling/ate-gress/internal/policy"
	"github.com/ate-tooling/ate-gress/internal/policyfile"
)

// claim compiles a selector and returns the claim of its policy, so that the
// tests ask the compiled selector, as Decide does.
func claim(t *testing.T, atespaces, names []string) policy.Claim {
	t.Helper()
	var p policyfile.Policy
	p.Name = "p"
	p.Spec.ActorSelector.Atespaces, p.Spec.ActorSelector.Names = atespaces, names
	p.Spec.Hosts = []policyfile.Host{{Host: "example.com"}}
	snap, results := policy.Compile([]policyfile.Policy{p})
	if results[0].Err != nil {
		t.Fatal(results[0].Err)
	}
	return snap.Claims("example.com")[0]
}

// labels returns every DNS label of up to n characters over a small alphabet
// that still has a letter, a digit and the hyphen.
func labels(n int) []string {
	var out []string
	var grow func(prefix string)
	grow = func(prefix string) {
		if isLabel(prefix) {
			out = append(out, prefix)
		}
		if len(prefix) == n {
			return
		}
		for _, c := range "ab0-" {
			grow(prefix + string(c))
		}
	}
	grow("")
	return out
}

func TestGlobReasoning(t *testing.T) {
	tests := []struct {
		p, q string
		// covers: q matches everything p matches. common: some label
		// matches both.
		covers, common bool
	}{
		{"a", "a", true, true},
		{"a", "b", false, false},
		{"a", "*", true, true},
		{"*", "a", false, true},
		{"*", "*", true, true},
		{"*", "**", true, true},
		{"a*", "a*", true, true},
		{"ab*", "a*", true, true},
		{"a*", "ab*", false, true},
		{"a*b", "a*", true, true},
		{"a*b", "*b", true, true},
		{"a*b", "a*a", false, false},
		{"a*", "*a", false, true},
		{"a*", "b*", false, false},
		{"a-*", "*-b", false, true},
		{"*a*", "*b*", false, true},
		{"a*b*a", "a*a", true, true},
		{"a*a", "a*b*a", false, true},
		{"ab", "a*b", true, true},
		{"aab", "a*ab", true, true},
		{"ab", "a*ab", false, false},
		{"*-", "*", true, false}, // no label ends in a hyphen
		{"-*", "*a", false, false},
	}
	all := labels(4)
	for _, tt := range tests {
		t.Run(tt.p+" vs "+tt.q, func(t *testing.T) {
			if got := globCovers(tt.q, tt.p); got != tt.covers {
				t.Errorf("globCovers(%q, %q) = %v, want %v", tt.q, tt.p, got, tt.covers)
			}
			w, state := commonLabel([]string{tt.p}, []string{tt.q})
			if got := state == overlapSome; got != tt.common {
				t.Errorf("commonLabel(%q, %q) = %q, %v; want a common label: %v", tt.p, tt.q, w, state, tt.common)
			}

			// The answers are checked against the compiled selectors on
			// every short label: they must never be wrong, though they may
			// be less than the whole truth.
			p, q := claim(t, []string{tt.p}, nil), claim(t, []string{tt.q}, nil)
			var both, onlyP int
			for _, l := range all {
				a := identity.Actor{Atespace: l, Name: "x"}
				switch {
				case p.Selects(a) && q.Selects(a):
					both++
				case p.Selects(a):
					onlyP++
				}
			}
			if selectorCovers(q, p) && onlyP > 0 {
				t.Errorf("%q is said to cover %q, but %d labels match only the latter", tt.q, tt.p, onlyP)
			}
			switch state {
			case overlapNone:
				if both > 0 {
					t.Errorf("%q and %q are said to be disjoint, but %d labels match both", tt.p, tt.q, both)
				}
			case overlapSome:
				if a := (identity.Actor{Atespace: w, Name: "x"}); !p.Selects(a) || !q.Selects(a) {
					t.Errorf("%q is given as matching both %q and %q, and does not", w, tt.p, tt.q)
				}
			}
		})
	}
}

// TestGlobReasoningExhaustive runs the same soundness check over every pair
// of short globs, where the table above only has the cases someone thought
// of.
func TestGlobReasoningExhaustive(t *testing.T) {
	var globs []string
	var grow func(prefix string)
	grow = func(prefix string) {
		if prefix != "" {
			globs = append(globs, prefix)
		}
		if len(prefix) == 3 {
			return
		}
		for _, c := range "a0-*" {
			grow(prefix + string(c))
		}
	}
	grow("")
	all := labels(4)
	matches := make(map[string]map[string]bool, len(globs))
	for _, g := range globs {
		c := claim(t, []string{g}, nil)
		matches[g] = map[string]bool{}
		for _, l := range all {
			if c.Selects(identity.Actor{Atespace: l, Name: "x"}) {
				matches[g][l] = true
			}
		}
	}
	for _, p := range globs {
		for _, q := range globs {
			both, onlyP := 0, 0
			for l := range matches[p] {
				if matches[q][l] {
					both++
				} else {
					onlyP++
				}
			}
			if globCovers(q, p) && onlyP > 0 {
				t.Fatalf("%q is said to cover %q, but %d labels match only the latter", q, p, onlyP)
			}
			switch w, state := commonLabel([]string{p}, []string{q}); state {
			case overlapNone:
				if both > 0 {
					t.Fatalf("%q and %q are said to be disjoint, but %d labels match both", p, q, both)
				}
			case overlapSome:
				if !matches[p][w] || !matches[q][w] {
					t.Fatalf("%q is given as matching both %q and %q, and does not", w, p, q)
				}
			case overlapUnknown:
				// Unknown must be rare enough to be useful: here it is
				// right only when no short label matches both.
				if both > 0 {
					t.Fatalf("%q and %q: %d labels match both, and no common label was found", p, q, both)
				}
			}
		}
	}
}

func TestSelectorOverlap(t *testing.T) {
	tests := []struct {
		pAtespaces, pNames, qAtespaces, qNames []string
		covers                                 bool
		state                                  overlap
	}{
		{nil, nil, nil, nil, true, overlapSome},
		{[]string{"research"}, nil, nil, nil, true, overlapSome},
		{nil, nil, []string{"research"}, nil, false, overlapSome},
		{nil, nil, []string{"*"}, []string{"**"}, true, overlapSome},
		{[]string{"research"}, []string{"bot-*"}, []string{"research", "ops"}, []string{"*"}, true, overlapSome},
		{[]string{"research", "billing"}, nil, []string{"research", "ops"}, nil, false, overlapSome},
		{[]string{"research"}, nil, []string{"billing"}, nil, false, overlapNone},
		// The atespaces overlap and the names cannot.
		{[]string{"team-*"}, []string{"bot"}, []string{"*-prod"}, []string{"agent"}, false, overlapNone},
		{[]string{"team-*"}, []string{"bot"}, []string{"*-prod"}, []string{"b*"}, false, overlapSome},
		// A selector that selects nobody: nothing can be proved from a
		// witness, and it is not called disjoint either.
		{[]string{"*-"}, nil, nil, nil, true, overlapUnknown},
		{nil, nil, []string{"*-"}, nil, false, overlapUnknown},
	}
	for _, tt := range tests {
		name := fmt.Sprintf("%v/%v vs %v/%v", tt.pAtespaces, tt.pNames, tt.qAtespaces, tt.qNames)
		t.Run(name, func(t *testing.T) {
			p, q := claim(t, tt.pAtespaces, tt.pNames), claim(t, tt.qAtespaces, tt.qNames)
			if got := selectorCovers(q, p); got != tt.covers {
				t.Errorf("selectorCovers = %v, want %v", got, tt.covers)
			}
			state, actor := selectorOverlap(p, q)
			if state != tt.state {
				t.Errorf("selectorOverlap = %v (%v), want %v", state, actor, tt.state)
			}
			if state == overlapSome && (!p.Selects(actor) || !q.Selects(actor)) {
				t.Errorf("%v is given as selected by both, and is not", actor)
			}
		})
	}
}
