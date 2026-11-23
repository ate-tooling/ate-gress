package pathmatch

import (
	"strings"
	"testing"
)

func TestCovers(t *testing.T) {
	tests := []struct {
		a, b         string
		aFold, bFold bool
		want         bool
	}{
		{a: "/", b: "/", want: true},
		{a: "/**", b: "/", want: false},
		{a: "/**", b: "/a", want: true},
		{a: "/**", b: "/a/*/**", want: true},
		{a: "/**", b: "/**", want: true},
		{a: "/**", b: "/v2/", want: false},
		{a: "/v2/", b: "/v2/", want: true},
		{a: "/v2", b: "/v2/", want: false},
		{a: "/v2/", b: "/v2", want: false},
		{a: "/*", b: "/v2", want: true},
		{a: "/*", b: "/v2/", want: false},
		{a: "/*/", b: "/v2/", want: true},
		{a: "/v2/*", b: "/v2/", want: false},
		{a: "/repos/acme/*", b: "/repos/acme/widget", want: true},
		{a: "/repos/acme/widget", b: "/repos/acme/*", want: false},
		{a: "/repos/acme/*", b: "/repos/acme/*/**", want: false},
		{a: "/repos/acme/*/**", b: "/repos/acme/*", want: false},
		{a: "/repos/acme/**", b: "/repos/acme/*", want: true},
		{a: "/repos/acme/**", b: "/repos/acme/*/**", want: true},
		{a: "/repos/acme/**", b: "/repos/acme", want: false},
		{a: "/repos/*/pulls", b: "/repos/acme/pulls", want: true},
		{a: "/repos/*/pulls", b: "/repos/acme/issues", want: false},
		{a: "/repos/*/pulls", b: "/repos/*/*", want: false},
		{a: "/*/*", b: "/repos/**", want: false},
		{a: "/repos/acme-evil", b: "/repos/acme", want: false},

		// Case: a case-insensitive template covers either spelling, and a
		// case-sensitive one covers a case-insensitive one only where there
		// is no letter to fold.
		{a: "/orgs/acme", aFold: true, b: "/orgs/ACME", want: true},
		{a: "/orgs/acme", aFold: true, b: "/ORGS/Acme", bFold: true, want: true},
		{a: "/orgs/acme", b: "/orgs/acme", bFold: true, want: false},
		{a: "/orgs/acme", b: "/orgs/ACME", want: false},
		{a: "/v2/123", b: "/v2/123", bFold: true, want: false}, // "v" folds
		{a: "/2/123", b: "/2/123", bFold: true, want: true},
		{a: "/*/acme", b: "/x/acme", bFold: true, want: false},
		{a: "/*/**", b: "/x/acme", bFold: true, want: true},
	}
	for _, tt := range tests {
		a, err := Compile(tt.a, tt.aFold)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Compile(tt.b, tt.bFold)
		if err != nil {
			t.Fatal(err)
		}
		if got := a.Covers(b); got != tt.want {
			t.Errorf("%q (fold=%v) covers %q (fold=%v) = %v, want %v", tt.a, tt.aFold, tt.b, tt.bFold, got, tt.want)
		}
		checkCovers(t, a, b)
	}
}

// witnesses returns paths t matches, chosen so that a template that does not
// cover t fails to match one of them: every wildcard is filled with a segment
// no sensible literal spells, "**" with one and with two of them, and every
// literal of a case-insensitive template is tried in both cases.
func witnesses(t *Template) []string {
	if len(t.segs) == 0 {
		return []string{"/"}
	}
	build := func(up bool, tailLen int) string {
		var b strings.Builder
		for _, s := range t.segs {
			b.WriteByte('/')
			switch s.kind {
			case one:
				b.WriteString("~w~")
			case tail:
				b.WriteString("~w~" + strings.Repeat("/~w~", tailLen-1))
			default:
				if up {
					b.WriteString(strings.ToUpper(s.lit))
				} else {
					b.WriteString(strings.ToLower(s.lit))
				}
			}
		}
		return b.String()
	}
	out := []string{strings.NewReplacer("**", "~w~", "*", "~w~").Replace(t.pattern), build(false, 1), build(false, 2)}
	if t.fold {
		out = append(out, build(true, 1), build(true, 2))
	} else {
		out = out[:1]
		out = append(out, strings.NewReplacer("**", "~w~/~w~", "*", "~w~").Replace(t.pattern))
	}
	return out
}

// checkCovers checks a.Covers(b) against Match on b's witnesses: every one
// must match a when a covers b, and one must not when it does not.
func checkCovers(t *testing.T, a, b *Template) {
	t.Helper()
	covers, all := a.Covers(b), true
	for _, w := range witnesses(b) {
		p, err := Canonicalize(w)
		if err != nil || !b.Match(p) {
			t.Fatalf("witness %q of %q: not a path it matches (%v)", w, b, err)
		}
		if !a.Match(p) {
			all = false
			if covers {
				t.Fatalf("%q (fold=%v) covers %q (fold=%v), but only the latter matches %q", a, a.fold, b, b.fold, p)
			}
		}
	}
	if !covers && all {
		t.Fatalf("%q (fold=%v) does not cover %q (fold=%v), but matches all its witnesses %q", a, a.fold, b, b.fold, witnesses(b))
	}
}

// FuzzCovers checks Covers against Match: a covering template matches every
// path the covered one does, and a template that does not cover another
// misses one of its witnesses.
func FuzzCovers(f *testing.F) {
	f.Add("/repos/acme/**", "/repos/acme/*", "/repos/acme/widget", false, false)
	f.Add("/orgs/acme", "/orgs/ACME", "/orgs/Acme", true, false)
	f.Add("/**", "/v2/", "/v2/", false, false)
	f.Add("/*/", "/v2/", "/v2/", false, true)
	f.Add("/", "/", "/", false, false)
	f.Fuzz(func(t *testing.T, pa, pb, raw string, foldA, foldB bool) {
		// "~" is a legal literal byte, and a literal spelling the witness
		// filler would make the witnesses say nothing.
		if strings.Contains(pa, "~") || strings.Contains(pb, "~") {
			return
		}
		a, err := Compile(pa, foldA)
		if err != nil {
			return
		}
		b, err := Compile(pb, foldB)
		if err != nil {
			return
		}
		checkCovers(t, a, b)
		if p, err := Canonicalize(raw); err == nil && a.Covers(b) && b.Match(p) && !a.Match(p) {
			t.Fatalf("%q covers %q, but only the latter matches %q", pa, pb, p)
		}
	})
}
