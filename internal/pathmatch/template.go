package pathmatch

import (
	"errors"
	"fmt"
	"strings"
)

// Template is a compiled path pattern. Patterns are absolute paths whose
// segments are one of:
//   - a literal, matched byte for byte (or ASCII case-insensitively);
//   - "*", matching exactly one non-empty segment;
//   - "**", matching one or more non-empty segments, allowed only as the last
//     segment.
//
// A pattern may end in "/" after a literal or "*", and then matches only
// paths with that one trailing slash: "/v2/" matches "/v2/" and not "/v2".
// Neither "*" nor "**" matches the empty segment a trailing slash leaves, so
// "/**" does not match "/v2/" and "/v2/*" does not match it either.
//
// The pattern "/" matches only the root path. A Template is immutable and safe
// for concurrent use.
type Template struct {
	pattern string
	segs    []segment
	fold    bool
}

type segmentKind uint8

const (
	literal segmentKind = iota
	one                 // *
	tail                // **
)

type segment struct {
	kind segmentKind
	lit  string
}

// Compile parses pattern. With caseInsensitive set, literal segments match
// ASCII case-insensitively. Canonicalize admits only ASCII, so this is plain
// ASCII folding and never Unicode folding (no "K" matching the Kelvin sign).
//
// Literal segments are held to a stricter rule than request paths: they may
// not contain "%", so a pattern can never be written to match an escaped form.
func Compile(pattern string, caseInsensitive bool) (*Template, error) {
	t := &Template{pattern: pattern, fold: caseInsensitive}
	if pattern == "" || pattern[0] != '/' {
		return nil, ErrNotAbsolute
	}
	if pattern == "/" {
		return t, nil
	}
	rest := pattern[1:]
	for {
		seg, after, more := strings.Cut(rest, "/")
		if seg == "" && !more {
			// A trailing slash, matched literally. The segment before it is
			// a literal or "*": a "**" with a segment after it was refused.
			t.segs = append(t.segs, segment{kind: literal})
			return t, nil
		}
		s, err := compileSegment(seg)
		if err != nil {
			return nil, fmt.Errorf("pattern %q: %w", pattern, err)
		}
		if s.kind == tail && more {
			return nil, fmt.Errorf("pattern %q: %w", pattern, errTailNotLast)
		}
		t.segs = append(t.segs, s)
		if !more {
			return t, nil
		}
		rest = after
	}
}

var (
	errTailNotLast   = errors.New(`"**" must be the last segment`)
	errEmbeddedStar  = errors.New(`"*" must be a whole segment`)
	errPercentInLit  = errors.New(`literal segments may not contain "%"`)
	errPatternSyntax = errors.New("invalid pattern segment")
)

func compileSegment(seg string) (segment, error) {
	switch seg {
	case "*":
		return segment{kind: one}, nil
	case "**":
		return segment{kind: tail}, nil
	}
	if strings.Contains(seg, "*") {
		return segment{}, errEmbeddedStar
	}
	if strings.Contains(seg, "%") {
		return segment{}, errPercentInLit
	}
	if err := checkSegment(seg); err != nil {
		return segment{}, fmt.Errorf("%w: %w", errPatternSyntax, err)
	}
	return segment{kind: literal, lit: seg}, nil
}

// String returns the pattern t was compiled from.
func (t *Template) String() string { return t.pattern }

// Match reports whether path matches t. The path must have come from
// Canonicalize; Match does not re-validate it. Match does not allocate.
func (t *Template) Match(path string) bool {
	rest, remaining := path[1:], path != "/"
	for _, s := range t.segs {
		if !remaining {
			return false
		}
		if s.kind == tail {
			// One or more segments, none of them the empty one a trailing
			// slash leaves. A canonical path has no other empty segment.
			return rest != "" && rest[len(rest)-1] != '/'
		}
		seg, after, more := strings.Cut(rest, "/")
		switch {
		case s.kind == one:
			if seg == "" {
				return false
			}
		case t.fold:
			if !strings.EqualFold(seg, s.lit) {
				return false
			}
		case seg != s.lit:
			return false
		}
		rest, remaining = after, more
	}
	return !remaining
}
