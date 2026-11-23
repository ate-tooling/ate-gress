package pathmatch

import "strings"

// Covers reports whether t matches every path o matches, which makes o
// redundant wherever t is also allowed. It is exact: when it returns false,
// some canonical path matches o and not t.
//
// Covers is for tools that lint policies. The request path does not use it.
func (t *Template) Covers(o *Template) bool {
	for i, s := range t.segs {
		if s.kind == tail {
			// "**" takes one or more segments, none of them the empty one a
			// trailing slash leaves; what kinds they are in o does not matter.
			rest := o.segs[min(i, len(o.segs)):]
			return len(rest) > 0 && !rest[len(rest)-1].trailingSlash()
		}
		if i >= len(o.segs) {
			return false
		}
		switch os := o.segs[i]; {
		case os.kind == tail:
			// o matches paths of any length from here, and t without a "**"
			// matches one length only.
			return false
		case s.kind == one:
			if os.trailingSlash() {
				return false
			}
		case os.kind != literal:
			return false
		case t.fold:
			if !strings.EqualFold(s.lit, os.lit) {
				return false
			}
		case s.lit != os.lit || (o.fold && hasLetter(os.lit)):
			// A case-sensitive literal does not cover the other spellings a
			// case-insensitive one matches.
			return false
		}
	}
	return len(o.segs) == len(t.segs)
}

// trailingSlash reports whether s is the empty literal a pattern's trailing
// slash compiles to.
func (s segment) trailingSlash() bool { return s.kind == literal && s.lit == "" }

func hasLetter(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i] | 0x20; 'a' <= c && c <= 'z' {
			return true
		}
	}
	return false
}
