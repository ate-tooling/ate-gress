// Package pathmatch canonicalizes HTTP request paths and matches them against
// compiled route templates.
//
// The Substrate egress gateway forwards :path exactly as the actor sent it: its
// HTTP connection managers set none of Envoy's normalization options. This
// package is therefore where ambiguous paths are refused. Canonicalize never
// repairs a path. Anything an upstream could read differently from the way a
// template reads it (an encoded separator, a dot segment, an empty segment)
// is an error, and the caller denies the request.
package pathmatch

import (
	"errors"
	"strings"
)

// Errors returned by Canonicalize. Callers deny on any of them; the distinct
// values exist so tests and logs can say which rule fired.
var (
	ErrNotAbsolute     = errors.New("path does not start with /")
	ErrEmptySegment    = errors.New("path has an empty segment")
	ErrDotSegment      = errors.New("path has a dot segment")
	ErrInvalidByte     = errors.New("path has a byte outside RFC 3986 pchar")
	ErrMalformedEscape = errors.New("path has a malformed percent-escape")
	ErrForbiddenEscape = errors.New("path percent-encodes a separator, dot, percent sign, or control byte")
)

// Canonicalize returns the path component of raw, the value of an HTTP/2
// :path or HTTP/1 request-target in origin form, with the query removed.
//
// It returns an error, and no path, if any of these hold:
//   - the path does not start with "/";
//   - any segment other than the single segment of "/" is empty, so "//" and
//     a trailing "/" are refused;
//   - any segment is "." or "..";
//   - any byte is not an RFC 3986 pchar or the start of a percent-escape, so
//     controls, spaces, non-ASCII, "\", and "#" are refused;
//   - a percent-escape is malformed, or decodes to "/", "\", ".", "%", or a
//     control byte.
//
// Under these rules, percent-decoding an accepted path once cannot introduce
// a separator or a dot segment, and a second decode cannot change it. An
// upstream that decodes before routing sees the same segments a template does.
//
// Canonicalize does not allocate. The returned string is a prefix of raw.
func Canonicalize(raw string) (string, error) {
	p, _, _ := strings.Cut(raw, "?")
	if p == "" || p[0] != '/' {
		return "", ErrNotAbsolute
	}
	if p == "/" {
		return p, nil
	}
	rest := p[1:]
	for {
		seg, after, more := strings.Cut(rest, "/")
		if err := checkSegment(seg); err != nil {
			return "", err
		}
		if !more {
			return p, nil
		}
		rest = after
	}
}

func checkSegment(seg string) error {
	switch seg {
	case "":
		return ErrEmptySegment
	case ".", "..":
		return ErrDotSegment
	}
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if c != '%' {
			if !isPchar(c) {
				return ErrInvalidByte
			}
			continue
		}
		if i+2 >= len(seg) || !isHex(seg[i+1]) || !isHex(seg[i+2]) {
			return ErrMalformedEscape
		}
		switch v := unhex(seg[i+1])<<4 | unhex(seg[i+2]); {
		case v == '/', v == '\\', v == '.', v == '%', v < 0x20, v == 0x7f:
			return ErrForbiddenEscape
		}
		i += 2
	}
	return nil
}

// isPchar reports whether c may appear unescaped in a path segment: RFC 3986
// unreserved, sub-delims, ":" and "@".
func isPchar(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	switch c {
	case '-', '.', '_', '~', // unreserved
		'!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', // sub-delims
		':', '@':
		return true
	}
	return false
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
