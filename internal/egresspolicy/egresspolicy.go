// Package egresspolicy reads a Substrate EgressPolicy manifest and works out
// which of a host's traffic the egress gateway hands to ate-gress.
//
// Substrate's EgressPolicy belongs to one actor and decides, per hostname and
// port, whether traffic is cleartext HTTP (an http rule), intercepted HTTPS
// (an https rule) or TLS forwarded undecrypted (a tls_passthrough rule). The
// gateway calls ate-gress for the first two and never for the third, so an
// EgressRoutePolicy on a passthrough host is not enforced.
//
// The matching here follows Substrate's own evaluator,
// internal/egresspolicy/egresspolicy.go in its repository, and the semantics
// its API documents on the EgressPolicy, HttpRule, HttpsRule and
// TlsPassthroughRule messages in api/ateapi/v1/ateapi.proto. It is written
// out again rather than imported because that evaluator is in an internal
// package of the Substrate module, which nothing outside it can import, and
// because what is needed is forty lines of hostname matching.
package egresspolicy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	utiljson "k8s.io/apimachinery/pkg/util/json"
	"k8s.io/apimachinery/pkg/util/validation"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
)

// Protocol is the member of an EgressRule that is set.
type Protocol string

const (
	HTTP           Protocol = "http"
	HTTPS          Protocol = "https"
	TLSPassthrough Protocol = "tlsPassthrough"
)

// Policy is a parsed EgressPolicy.
type Policy struct {
	// Atespace is metadata.atespace, the atespace of the actor the policy
	// belongs to, or empty when the manifest leaves its metadata out.
	Atespace string
	Rules    []Rule
}

// Rule is one EgressRule.
type Rule struct {
	// Index is the rule's position in rules.
	Index    int
	Protocol Protocol
	// Hostnames are the rule's patterns, as written.
	Hostnames []string
	// AllPorts is set for ports.all; otherwise Ports lists the numbers, with
	// the protocol's default filled in.
	AllPorts bool
	Ports    []int

	patterns []pattern
}

// Field returns the path of the rule in the manifest, such as
// "rules[1].tlsPassthrough".
func (r Rule) Field() string { return fmt.Sprintf("rules[%d].%s", r.Index, r.Protocol) }

// Parse reads a manifest in the form `kubectl ate create egress-policy -f`
// takes and `kubectl ate get egress-policy -o yaml` prints: one YAML or JSON
// document holding the EgressPolicy as protobuf JSON, with metadata optional.
// Like kubectl ate, it accepts field names in either their JSON (camelCase)
// or their proto (snake_case) form, and refuses an unknown field: a rule this
// package misread would make its answer wrong.
//
// Parse checks only what its answer depends on: each rule's protocol,
// hostnames and ports. Effects and metadata are not validated.
func Parse(data []byte) (*Policy, error) {
	obj, err := singleDocument(data)
	if err != nil {
		return nil, err
	}
	top, err := fields(obj, "metadata", "rules")
	if err != nil {
		if _, isManifest := obj["apiVersion"]; isManifest {
			return nil, fmt.Errorf("%w; a Substrate EgressPolicy manifest has only metadata and rules, and no apiVersion or kind", err)
		}
		return nil, err
	}
	p := &Policy{}
	if meta, ok := top["metadata"].(map[string]any); ok {
		p.Atespace, _ = meta["atespace"].(string)
	}
	rules, ok := top["rules"].([]any)
	if top["rules"] != nil && !ok {
		return nil, errors.New("rules: not a list")
	}
	for i, raw := range rules {
		r, err := parseRule(i, raw)
		if err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}
		p.Rules = append(p.Rules, r)
	}
	return p, nil
}

func singleDocument(data []byte) (map[string]any, error) {
	var found map[string]any
	docs := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	for {
		doc, err := docs.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		raw, err := yaml.YAMLToJSONStrict(doc)
		if err != nil {
			return nil, err
		}
		var v any
		if err := utiljson.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		if v == nil {
			continue
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("not an object")
		}
		if found != nil {
			return nil, errors.New("more than one document; an EgressPolicy manifest holds one")
		}
		found = m
	}
	if found == nil {
		return nil, errors.New("manifest is empty")
	}
	return found, nil
}

// fields checks that v is an object with only the named fields, each given
// in its camelCase form, and returns it keyed by those names whichever form
// the manifest used.
func fields(v any, names ...string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("not an object")
	}
	out := make(map[string]any, len(m))
	for k, value := range m {
		name := k
		if i := slices.IndexFunc(names, func(n string) bool { return snakeCase(n) == k }); i >= 0 {
			name = names[i]
		}
		if !slices.Contains(names, name) {
			return nil, fmt.Errorf("unknown field %q", k)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("field %q is set twice", name)
		}
		out[name] = value
	}
	return out, nil
}

func snakeCase(camel string) string {
	var b strings.Builder
	for i := 0; i < len(camel); i++ {
		if c := camel[i]; 'A' <= c && c <= 'Z' {
			b.WriteByte('_')
			b.WriteByte(c + 'a' - 'A')
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// Ports an http or https rule that names none reads as. Substrate's API
// server fills these in when it stores a policy.
const (
	defaultHTTPPort  = 80
	defaultHTTPSPort = 443
)

func parseRule(index int, raw any) (Rule, error) {
	members, err := fields(raw, string(HTTP), string(HTTPS), string(TLSPassthrough))
	if err != nil {
		return Rule{}, err
	}
	// A null member is an unset one, as in protobuf JSON.
	for k, v := range members {
		if v == nil {
			delete(members, k)
		}
	}
	if len(members) != 1 {
		return Rule{}, errors.New("exactly one of http, https and tlsPassthrough must be set")
	}
	r := Rule{Index: index}
	var body any
	for k, v := range members {
		r.Protocol, body = Protocol(k), v
	}
	allowed := []string{"hostnames", "ports", "effects"}
	if r.Protocol == TLSPassthrough {
		allowed = allowed[:2] // a passthrough rule has no effects
	}
	rule, err := fields(body, allowed...)
	if err != nil {
		return Rule{}, fmt.Errorf("%s: %w", r.Protocol, err)
	}

	hostnames, ok := rule["hostnames"].([]any)
	if !ok || len(hostnames) == 0 {
		return Rule{}, fmt.Errorf("%s.hostnames: at least one hostname is required", r.Protocol)
	}
	for _, h := range hostnames {
		s, _ := h.(string)
		pat, err := parsePattern(s)
		if err != nil {
			return Rule{}, fmt.Errorf("%s.hostnames: %w", r.Protocol, err)
		}
		r.Hostnames = append(r.Hostnames, s)
		r.patterns = append(r.patterns, pat)
	}

	switch {
	case rule["ports"] != nil:
		if r.AllPorts, r.Ports, err = parsePorts(rule["ports"]); err != nil {
			return Rule{}, fmt.Errorf("%s.ports: %w", r.Protocol, err)
		}
	case r.Protocol == HTTP:
		r.Ports = []int{defaultHTTPPort}
	case r.Protocol == HTTPS:
		r.Ports = []int{defaultHTTPSPort}
	default:
		return Rule{}, fmt.Errorf("%s.ports: required", r.Protocol)
	}
	return r, nil
}

func parsePorts(raw any) (all bool, numbers []int, err error) {
	ports, err := fields(raw, "all", "numbers")
	if err != nil {
		return false, nil, err
	}
	list, _ := ports["numbers"].([]any)
	if ports["numbers"] != nil && list == nil {
		return false, nil, errors.New("numbers: not a list")
	}
	all = ports["all"] != nil
	if all == (len(list) > 0) {
		return false, nil, errors.New("exactly one of all and numbers must be set")
	}
	for _, v := range list {
		n, ok := portNumber(v)
		if !ok {
			return false, nil, fmt.Errorf("numbers: %v is not a port number", v)
		}
		numbers = append(numbers, n)
	}
	return all, numbers, nil
}

// portNumber reads an int32 as protobuf JSON spells it: a number, or the same
// in a string.
func portNumber(v any) (int, bool) {
	var n int64
	switch v := v.(type) {
	case int64:
		n = v
	case float64:
		if v != math.Trunc(v) {
			return 0, false
		}
		n = int64(v)
	case string:
		parsed, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return 0, false
		}
		n = parsed
	default:
		return 0, false
	}
	return int(n), 1 <= n && n <= 65535
}

// pattern is one hostname pattern: an exact name, "*." and a name for exactly
// one leftmost label, or "*" for every name and every address.
type pattern struct {
	name     string
	wildcard bool
	any      bool
}

// Ranks, most specific first. Substrate picks the deciding rule by the most
// specific matching pattern, then by a named port over all ports.
const (
	rankExact = iota
	rankWildcard
	rankAny
)

func parsePattern(raw string) (pattern, error) {
	if raw == "*" {
		return pattern{any: true}, nil
	}
	name, wildcard := strings.CutPrefix(raw, "*.")
	if !isHostname(name) {
		return pattern{}, fmt.Errorf("%q is not a valid hostname pattern", raw)
	}
	return pattern{name: name, wildcard: wildcard}, nil
}

// isHostname reports whether name is a lowercase DNS-1123 subdomain whose
// last label is not all digits, which is what Substrate takes for a name
// rather than an address.
func isHostname(name string) bool {
	if len(validation.IsDNS1123Subdomain(name)) != 0 {
		return false
	}
	last := name[strings.LastIndexByte(name, '.')+1:]
	return strings.Trim(last, "0123456789") != ""
}

func (p pattern) rank() int {
	switch {
	case p.any:
		return rankAny
	case p.wildcard:
		return rankWildcard
	}
	return rankExact
}

func (p pattern) matches(d destination) bool {
	switch {
	case p.any:
		return true
	case d.ip:
		return false // an address is matched by "*" alone
	case !p.wildcard:
		return d.name == p.name
	}
	label, found := strings.CutSuffix(d.name, "."+p.name)
	return found && label != "" && !strings.Contains(label, ".")
}

type destination struct {
	name string
	ip   bool
}

// match returns the pattern of r that matches d most specifically.
func (r Rule) match(d destination) (best int, ok bool) {
	for i, p := range r.patterns {
		if p.matches(d) && (!ok || p.rank() < r.patterns[best].rank()) {
			best, ok = i, true
		}
	}
	return best, ok
}

func (r Rule) matchesPort(port int) bool {
	if port == OtherPorts {
		return r.AllPorts
	}
	return r.AllPorts || slices.Contains(r.Ports, port)
}

// OtherPorts is the Port of a Match that holds for every port no rule
// matching the host names.
const OtherPorts = 0

// Match says which rule decides a host's traffic of one kind on one port.
type Match struct {
	Port int
	// Rule is the deciding rule, and Pattern the hostname pattern of it that
	// matched.
	Rule    Rule
	Pattern string
}

// Reach is what a policy does with one host's traffic, port by port. A port
// in none of the lists is one the gateway refuses.
type Reach struct {
	// HTTP lists the ports on which the actor may send cleartext HTTP to the
	// host. ate-gress sees those requests.
	HTTP []Match
	// HTTPS lists the ports on which TLS to the host is intercepted.
	// ate-gress sees those requests.
	HTTPS []Match
	// Passthrough lists the ports on which TLS to the host is forwarded
	// undecrypted. ate-gress never sees that traffic.
	Passthrough []Match
}

// Reach works out how p treats host, a lowercase hostname or an IP address,
// on every port a rule matching it names, and on all the others if a matching
// rule names all ports.
//
// Cleartext and TLS are decided separately, as the gateway decides them: a
// request by the http rules, and a TLS connection, at its ClientHello, by the
// https and tls_passthrough rules together. Within each, the deciding rule is
// the one whose matching pattern is most specific, then the one that names
// the port over one that names all ports. Substrate refuses a policy in which
// two rules tie; given one anyway, the earlier rule wins here.
func (p *Policy) Reach(host string) Reach {
	d := destination{name: host}
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		d.ip = true
	} else if !isHostname(host) {
		return Reach{} // not a name Substrate allows any rule to match
	}

	type candidate struct {
		rule    Rule
		pattern int
	}
	var matching []candidate
	ports := []int{}
	for _, r := range p.Rules {
		i, ok := r.match(d)
		if !ok {
			continue
		}
		matching = append(matching, candidate{r, i})
		ports = append(ports, r.Ports...)
		if r.AllPorts {
			ports = append(ports, OtherPorts)
		}
	}
	slices.Sort(ports)
	ports = slices.Compact(ports)
	// OtherPorts sorts first; report it last.
	if len(ports) > 0 && ports[0] == OtherPorts {
		ports = append(ports[1:], OtherPorts)
	}

	decide := func(port int, protocols ...Protocol) (Match, bool) {
		var best *candidate
		for i := range matching {
			c := &matching[i]
			if !slices.Contains(protocols, c.rule.Protocol) || !c.rule.matchesPort(port) {
				continue
			}
			if best == nil || beats(c.rule, c.pattern, best.rule, best.pattern) {
				best = c
			}
		}
		if best == nil {
			return Match{}, false
		}
		return Match{Port: port, Rule: best.rule, Pattern: best.rule.Hostnames[best.pattern]}, true
	}

	var reach Reach
	for _, port := range ports {
		if m, ok := decide(port, HTTP); ok {
			reach.HTTP = append(reach.HTTP, m)
		}
		if d.ip {
			continue // TLS rules match the SNI, which is never an address
		}
		if m, ok := decide(port, HTTPS, TLSPassthrough); ok {
			if m.Rule.Protocol == HTTPS {
				reach.HTTPS = append(reach.HTTPS, m)
			} else {
				reach.Passthrough = append(reach.Passthrough, m)
			}
		}
	}
	return reach
}

func beats(a Rule, ap int, b Rule, bp int) bool {
	if ra, rb := a.patterns[ap].rank(), b.patterns[bp].rank(); ra != rb {
		return ra < rb
	}
	return !a.AllPorts && b.AllPorts
}

// Seen reports whether ate-gress sees any of the host's traffic.
func (r Reach) Seen() bool { return len(r.HTTP) > 0 || len(r.HTTPS) > 0 }
