package pathmatch

import (
	"errors"
	"fmt"
	"strings"
)

// Template is a compiled path pattern. Patterns are absolute paths whose
// segments are one of:
//   - a literal, matched byte for byte (or ASCII case-insensitively);
//   - "*", matching exactly one segment;
//   - "**", matching one or more segments, allowed only as the last segment.
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
			return true
		}
		seg, after, more := strings.Cut(rest, "/")
		switch {
		case s.kind == one:
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
