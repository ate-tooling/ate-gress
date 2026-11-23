package lint

import (
	"path"
	"strings"

	"github.com/ate-tooling/ate-gress/internal/identity"
	"github.com/ate-tooling/ate-gress/internal/policy"
)

// The functions here reason about actor selectors without an actor in hand:
// whether one policy's selector takes in another's, and whether two can
// select the same actor. A selector is two lists of globs in which "*"
// matches any run of characters, over atespaces and names that are DNS
// labels.
//
// Each answer is one-sided. "Covers" and "disjoint" are returned only when
// they hold for every string, which is more than every label, so they are
// never claimed wrongly; a definite overlap is returned only with an actor
// that both selectors were asked about and select. What falls between is
// reported as unknown.

// selectorCovers reports whether q provably selects every actor p selects.
func selectorCovers(q, p policy.Claim) bool {
	return globsCover(q.Atespaces, p.Atespaces) && globsCover(q.Names, p.Names)
}

// globsCover reports whether every string a glob of ps matches is matched by
// one of qs. A nil list matches everything.
func globsCover(qs, ps []string) bool {
	if qs == nil {
		return true
	}
	if ps == nil {
		ps = []string{"*"}
	}
	for _, p := range ps {
		covered := false
		for _, q := range qs {
			if globCovers(q, p) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// globCovers reports whether q matches every string p matches. It matches q
// against p's own text: a "*" in p then stands for a run only a "*" in q can
// take in, and a "*" in q that takes it in takes in whatever it expands to.
// Globs hold only [a-z0-9*-], so path.Match reads q as literals and "*"
// wildcards, exactly as the policy compiler does.
func globCovers(q, p string) bool {
	ok, _ := path.Match(q, p)
	return ok
}

// overlap is what is known about whether two selectors share an actor.
type overlap uint8

const (
	overlapUnknown overlap = iota
	overlapNone            // provably no actor is selected by both
	overlapSome            // the returned actor is selected by both
)

// selectorOverlap works out whether p and q select a common actor, and
// returns one when they provably do.
func selectorOverlap(p, q policy.Claim) (overlap, identity.Actor) {
	atespace, a := commonLabel(p.Atespaces, q.Atespaces)
	name, n := commonLabel(p.Names, q.Names)
	if a == overlapNone || n == overlapNone {
		return overlapNone, identity.Actor{}
	}
	actor := identity.Actor{Atespace: atespace, Name: name}
	// The actor is evidence only if the compiled selectors agree: this asks
	// the code that decides requests, not the reasoning above.
	if a == overlapSome && n == overlapSome && p.Selects(actor) && q.Selects(actor) {
		return overlapSome, actor
	}
	return overlapUnknown, identity.Actor{}
}

// commonLabel looks for a DNS label that a glob of each list matches.
func commonLabel(ps, qs []string) (string, overlap) {
	if ps == nil {
		ps = []string{"*"}
	}
	if qs == nil {
		qs = []string{"*"}
	}
	result := overlapNone
	for _, p := range ps {
		for _, q := range qs {
			w, ok := commonString(p, q)
			if !ok {
				continue // no string at all matches both
			}
			result = overlapUnknown
			// The shortest common string may not be a label ("" for two
			// "*"); padding it is a guess that the check below confirms.
			for _, c := range []string{w, "a" + w, w + "a", "a" + w + "a"} {
				if isLabel(c) && globCovers(p, c) && globCovers(q, c) {
					return c, overlapSome
				}
			}
		}
	}
	return "", result
}

// commonString returns a string both globs match, or false if there is none.
// It walks the two patterns together. When both are at a "*", neither needs
// to take a character: any the two would share can be dropped from the
// string.
func commonString(p, q string) (string, bool) {
	type state struct{ i, j int }
	dead := map[state]bool{}
	var walk func(i, j int) (string, bool)
	walk = func(i, j int) (string, bool) {
		if i == len(p) && j == len(q) {
			return "", true
		}
		s := state{i, j}
		if dead[s] {
			return "", false
		}
		pStar := i < len(p) && p[i] == '*'
		qStar := j < len(q) && q[j] == '*'
		if pStar {
			if w, ok := walk(i+1, j); ok { // p's "*" ends
				return w, true
			}
			if j < len(q) && !qStar {
				if w, ok := walk(i, j+1); ok { // p's "*" takes q's literal
					return string(q[j]) + w, true
				}
			}
		}
		if qStar {
			if w, ok := walk(i, j+1); ok {
				return w, true
			}
			if i < len(p) && !pStar {
				if w, ok := walk(i+1, j); ok {
					return string(p[i]) + w, true
				}
			}
		}
		if !pStar && !qStar && i < len(p) && j < len(q) && p[i] == q[j] {
			if w, ok := walk(i+1, j+1); ok {
				return string(p[i]) + w, true
			}
		}
		dead[s] = true
		return "", false
	}
	return walk(0, 0)
}

// isLabel reports whether s is an RFC 1123 label, which every atespace and
// actor name is.
func isLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	return strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789-") == ""
}
