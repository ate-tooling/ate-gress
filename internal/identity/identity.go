// Package identity parses the actor identity the Substrate egress gateway
// attaches to each request it forwards to ate-gress.
//
// The gateway reads the actor's SPIFFE ID from the URI SAN of the certificate
// atunnel presented on the outer CONNECT, and passes it to ext_proc as the
// dev.ate.actor.identity filter-state attribute. Its form is
// spiffe://<trust-domain>/worker-for-actor/<atespace>/<name>, built by
// WorkerForActorSPIFFEID in substrate's internal/resources/spiffe.go.
package identity

import (
	"errors"
	"fmt"
	"strings"
)

// DefaultTrustDomain is the trust domain Substrate mints actor identities in.
const DefaultTrustDomain = "substrate-actor.local"

// Actor names one Substrate actor.
type Actor struct {
	Atespace string
	Name     string
}

// String returns "<atespace>/<name>".
func (a Actor) String() string { return a.Atespace + "/" + a.Name }

// ErrMalformed is returned for any identity Parse does not accept.
var ErrMalformed = errors.New("malformed actor identity")

// Parser parses actor SPIFFE IDs in one trust domain.
type Parser struct {
	prefix string
}

// NewParser returns a Parser for IDs in trustDomain.
func NewParser(trustDomain string) (*Parser, error) {
	if !isDNSLabelSequence(trustDomain) {
		return nil, fmt.Errorf("invalid trust domain %q", trustDomain)
	}
	return &Parser{prefix: "spiffe://" + trustDomain + "/worker-for-actor/"}, nil
}

// Parse returns the actor id names. It accepts only the exact form Substrate
// mints: no userinfo, port, query, fragment, escapes, or extra segments, and
// atespace and name must each be an RFC 1123 label, as Substrate requires.
// Parse does not allocate.
func (p *Parser) Parse(id string) (Actor, error) {
	rest, ok := strings.CutPrefix(id, p.prefix)
	if !ok {
		return Actor{}, ErrMalformed
	}
	return ParseActor(rest)
}

// ParseActor reads an actor as Actor.String writes it, "<atespace>/<name>".
// It accepts exactly the actors Parse accepts, and does not allocate.
func ParseActor(s string) (Actor, error) {
	atespace, name, ok := strings.Cut(s, "/")
	if !ok || !isDNSLabel(atespace) || !isDNSLabel(name) {
		return Actor{}, ErrMalformed
	}
	return Actor{Atespace: atespace, Name: name}, nil
}

// isDNSLabel reports whether s is an RFC 1123 label: 1-63 characters of
// [a-z0-9-], starting and ending with an alphanumeric.
func isDNSLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

func isDNSLabelSequence(s string) bool {
	if len(s) > 253 {
		return false
	}
	for label := range strings.SplitSeq(s, ".") {
		if !isDNSLabel(label) {
			return false
		}
	}
	return true
}
