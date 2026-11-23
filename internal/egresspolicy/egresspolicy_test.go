package egresspolicy

import (
	"fmt"
	"strings"
	"testing"
)

// substrateExample is the EgressPolicy example from Substrate's own API
// documentation (tools/apitool/internal/examples/grpc/EgressPolicy.yaml),
// which is what `kubectl ate get egress-policy -o yaml` prints.
const substrateExample = `
metadata:
  atespace: prod
  name: default
  uid: 1a2b3c4d-5e6f-4a3b-8c9d-0e1f2a3b4c5d
  version: "2"
  createTime: "2026-08-01T18:22:04Z"
  updateTime: "2026-08-02T11:05:40Z"
rules:
- https:
    hostnames:
    - api.example.com
    effects:
      replaceHeaders:
      - header: Authorization
        prefix: 'Bearer '
        credentialUri: ate-secret://example-provider/prod/checkout-api-key
- tlsPassthrough:
    hostnames:
    - '*.example.com'
    ports:
      numbers:
      - 443
`

func mustParse(t *testing.T, manifest string) *Policy {
	t.Helper()
	p, err := Parse([]byte(manifest))
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, manifest)
	}
	return p
}

func TestParse(t *testing.T) {
	p := mustParse(t, substrateExample)
	if p.Atespace != "prod" {
		t.Errorf("Atespace = %q", p.Atespace)
	}
	got := fmt.Sprintf("%v", p.Rules)
	for i, want := range []struct {
		field string
		ports []int
	}{{"rules[0].https", []int{443}}, {"rules[1].tlsPassthrough", []int{443}}} {
		r := p.Rules[i]
		if r.Field() != want.field || fmt.Sprint(r.Ports) != fmt.Sprint(want.ports) || r.AllPorts {
			t.Errorf("rule %d = %s ports %v all %v, want %s ports %v (%s)", i, r.Field(), r.Ports, r.AllPorts, want.field, want.ports, got)
		}
	}

	// The forms protobuf JSON also accepts: JSON, proto field names, a port
	// as a string, and no metadata.
	p = mustParse(t, `{"rules":[{"tls_passthrough":{"hostnames":["*"],"ports":{"all":{}}}},{"http":{"hostnames":["a.example.com"],"ports":{"numbers":["8080", 8081]}}}]}`)
	if r := p.Rules[0]; r.Protocol != TLSPassthrough || !r.AllPorts {
		t.Errorf("rule 0 = %+v, want a passthrough rule on all ports", r)
	}
	if r := p.Rules[1]; r.Protocol != HTTP || fmt.Sprint(r.Ports) != "[8080 8081]" {
		t.Errorf("rule 1 = %+v, want an http rule on 8080 and 8081", r)
	}
	if p := mustParse(t, "rules:\n- http:\n    hostnames: [a.example.com]\n"); fmt.Sprint(p.Rules[0].Ports) != "[80]" {
		t.Errorf("an http rule without ports reads as %v, want port 80", p.Rules[0].Ports)
	}
	if p := mustParse(t, "metadata: {atespace: a}\n"); len(p.Rules) != 0 {
		t.Errorf("a policy without rules has %d", len(p.Rules))
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct{ name, manifest, wantErr string }{
		{"empty", "# nothing\n", "manifest is empty"},
		{"two documents", "rules: []\n---\nrules: []\n", "more than one document"},
		{"a list", "- https: {hostnames: [a.example.com]}\n", "not an object"},
		{"an EgressRoutePolicy", "apiVersion: ategress.ate-tooling.github.io/v1alpha1\nkind: EgressRoutePolicy\nspec: {}\n", "no apiVersion or kind"},
		{"unknown top-level field", "rule: []\n", `unknown field "rule"`},
		// A misspelled member must not read as a rule that matches nothing.
		{"misspelled member", "rules:\n- tlsPasthrough: {hostnames: [a.example.com], ports: {all: {}}}\n", `rules[0]: unknown field "tlsPasthrough"`},
		{"misspelled rule field", "rules:\n- https: {hostname: [a.example.com]}\n", `rules[0]: https: unknown field "hostname"`},
		{"no member", "rules:\n- {}\n", "exactly one of http, https and tlsPassthrough"},
		{"two members", "rules:\n- http: {hostnames: [a.example.com]}\n  https: {hostnames: [a.example.com]}\n", "exactly one of"},
		{"both spellings", "rules:\n- tlsPassthrough: {hostnames: [a.example.com], ports: {all: {}}}\n  tls_passthrough: {hostnames: [a.example.com], ports: {all: {}}}\n", "set twice"},
		{"no hostnames", "rules:\n- https: {}\n", "at least one hostname"},
		{"passthrough without ports", "rules:\n- tlsPassthrough: {hostnames: [a.example.com]}\n", "ports: required"},
		{"effects on passthrough", "rules:\n- tlsPassthrough: {hostnames: [a.example.com], ports: {all: {}}, effects: {}}\n", `unknown field "effects"`},
		{"all and numbers", "rules:\n- https: {hostnames: [a.example.com], ports: {all: {}, numbers: [443]}}\n", "exactly one of all and numbers"},
		{"empty ports", "rules:\n- https: {hostnames: [a.example.com], ports: {}}\n", "exactly one of all and numbers"},
		{"port out of range", "rules:\n- https: {hostnames: [a.example.com], ports: {numbers: [70000]}}\n", "not a port number"},
		{"port zero", "rules:\n- https: {hostnames: [a.example.com], ports: {numbers: [0]}}\n", "not a port number"},
		{"uppercase hostname", "rules:\n- https: {hostnames: [API.example.com]}\n", "not a valid hostname pattern"},
		{"inner wildcard", "rules:\n- https: {hostnames: [api.*.example.com]}\n", "not a valid hostname pattern"},
		{"partial-label wildcard", "rules:\n- https: {hostnames: [\"*api.example.com\"]}\n", "not a valid hostname pattern"},
		{"IP address", "rules:\n- https: {hostnames: [10.0.0.1]}\n", "not a valid hostname pattern"},
		{"hostname with port", "rules:\n- https: {hostnames: [\"api.example.com:443\"]}\n", "not a valid hostname pattern"},
		{"trailing dot", "rules:\n- https: {hostnames: [api.example.com.]}\n", "not a valid hostname pattern"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.manifest))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Parse() error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

// describe renders a Reach as "kind port rule; ..." for comparison.
func describe(r Reach) string {
	var out []string
	add := func(kind string, ms []Match) {
		for _, m := range ms {
			port := fmt.Sprint(m.Port)
			if m.Port == OtherPorts {
				port = "other"
			}
			out = append(out, fmt.Sprintf("%s %s rules[%d] %s", kind, port, m.Rule.Index, m.Pattern))
		}
	}
	add("http", r.HTTP)
	add("https", r.HTTPS)
	add("passthrough", r.Passthrough)
	return strings.Join(out, "; ")
}

func TestReach(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
		// host to what Reach must say about it.
		want map[string]string
	}{
		{
			name:     "Substrate's example: the exact https rule outranks the wildcard passthrough",
			manifest: substrateExample,
			want: map[string]string{
				"api.example.com":        "https 443 rules[0] api.example.com",
				"files.example.com":      "passthrough 443 rules[1] *.example.com",
				"example.com":            "", // "*.example.com" needs exactly one more label
				"a.files.example.com":    "",
				"api.example.com.evil.x": "",
			},
		},
		{
			name: "the exact passthrough rule outranks the wildcard https",
			manifest: `
rules:
- https: {hostnames: ["*.example.com"]}
- tlsPassthrough: {hostnames: [api.example.com], ports: {numbers: [443]}}
`,
			want: map[string]string{
				"api.example.com":   "passthrough 443 rules[1] api.example.com",
				"files.example.com": "https 443 rules[0] *.example.com",
			},
		},
		{
			name: "a named port outranks all ports on the same pattern",
			manifest: `
rules:
- tlsPassthrough: {hostnames: [api.example.com], ports: {all: {}}}
- https: {hostnames: [api.example.com], ports: {numbers: [443]}}
`,
			want: map[string]string{
				"api.example.com": "https 443 rules[1] api.example.com; passthrough other rules[0] api.example.com",
			},
		},
		{
			name: "a more specific name outranks a named port",
			manifest: `
rules:
- tlsPassthrough: {hostnames: ["*"], ports: {numbers: [443]}}
- https: {hostnames: ["*.example.com"], ports: {all: {}}}
`,
			want: map[string]string{
				"api.example.com": "https 443 rules[1] *.example.com; https other rules[1] *.example.com",
				"example.org":     "passthrough 443 rules[0] *",
			},
		},
		{
			name: "cleartext and TLS are decided separately, port by port",
			manifest: `
rules:
- http: {hostnames: [api.example.com]}
- http: {hostnames: ["*.example.com"], ports: {numbers: [8080]}}
- tlsPassthrough: {hostnames: [api.example.com], ports: {numbers: [443, 8443]}}
- https: {hostnames: [api.example.com], ports: {numbers: [9443]}}
`,
			want: map[string]string{
				"api.example.com": "http 80 rules[0] api.example.com; http 8080 rules[1] *.example.com; https 9443 rules[3] api.example.com; " +
					"passthrough 443 rules[2] api.example.com; passthrough 8443 rules[2] api.example.com",
				"files.example.com": "http 8080 rules[1] *.example.com",
			},
		},
		{
			name: "a rule's most specific matching pattern is the one that ranks it",
			manifest: `
rules:
- https: {hostnames: ["*", api.example.com]}
- tlsPassthrough: {hostnames: ["*.example.com"], ports: {numbers: [443]}}
`,
			want: map[string]string{
				"api.example.com":   "https 443 rules[0] api.example.com",
				"files.example.com": "passthrough 443 rules[1] *.example.com",
				"example.org":       "https 443 rules[0] *",
			},
		},
		{
			name: "an address is matched by \"*\" alone, and only for cleartext",
			manifest: `
rules:
- http: {hostnames: ["*"]}
- https: {hostnames: ["*"]}
`,
			want: map[string]string{
				"10.0.0.1": "http 80 rules[0] *",
				// A name whose last label is all digits is not one Substrate
				// matches at all.
				"host.123": "",
			},
		},
		{
			name:     "no rules",
			manifest: "rules: []\n",
			want:     map[string]string{"api.example.com": ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := mustParse(t, tt.manifest)
			for host, want := range tt.want {
				reach := p.Reach(host)
				if got := describe(reach); got != want {
					t.Errorf("Reach(%q) =\n  %s\nwant\n  %s", host, got, want)
				}
				if seen := strings.Contains(want, "http"); reach.Seen() != seen {
					t.Errorf("Reach(%q).Seen() = %v, want %v", host, reach.Seen(), seen)
				}
			}
		})
	}
}
