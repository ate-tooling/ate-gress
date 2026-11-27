package ctl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/ate-tooling/ate-gress/internal/identity"
	"github.com/ate-tooling/ate-gress/internal/policy"
)

// testFile is a test file: the requests a policy set must allow, deny and
// audit, grouped by the actor that sends them. docs/ategressctl.md describes
// the format for the people who write it.
type testFile struct {
	// Policies are the policy files the tests run against, relative to the
	// test file; not "-". -f on the command line replaces them.
	Policies []string    `json:"policies,omitempty"`
	Tests    []testGroup `json:"tests"`
}

type testGroup struct {
	// Name says what the group is about, for the report.
	Name string `json:"name,omitempty"`
	// Actor is "<atespace>/<name>".
	Actor string        `json:"actor"`
	Allow []expectation `json:"allow,omitempty"`
	Deny  []expectation `json:"deny,omitempty"`
	Audit []expectation `json:"audit,omitempty"`
}

// expectation is one request and what must come of it. In a test file it is
// either the request alone, "GET https://host/path", or a mapping that also
// pins down why.
type expectation struct {
	Request string `json:"request"`
	// Reason, Policy and Template, when set, must equal the decision's.
	Reason   string `json:"reason,omitempty"`
	Policy   string `json:"policy,omitempty"`
	Template string `json:"template,omitempty"`
}

func (e *expectation) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		return json.Unmarshal(data, &e.Request)
	}
	type plain expectation
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode((*plain)(e))
}

// reasons lists the reasons Decide gives for each outcome, so that a
// misspelled one in a test file is an error and not a test that can never
// pass.
//
// invalid_policy is a reason Decide gives, for a host that only rejected
// policies claim for the actor: a denial when one of them is Enforce, and an
// audit when all are Audit. test refuses a set with a rejected policy today,
// so no case can pass with it, but a test file that names it is not
// misspelled.
var reasons = map[string][]policy.Reason{
	outcomeAllow: {policy.ReasonRoute, policy.ReasonUnclaimed},
	outcomeDeny:  {policy.ReasonNoRoute, policy.ReasonPath, policy.ReasonInvalidPolicy, policy.ReasonAuthority},
	outcomeAudit: {policy.ReasonNoRoute, policy.ReasonPath, policy.ReasonInvalidPolicy},
}

// testCase is one expectation, ready to run.
type testCase struct {
	// ID is the case's place in the test file, such as "tests[0].deny[2]".
	ID      string
	Group   string
	Actor   identity.Actor
	Request string
	request request
	Want    decision
}

// parseTestFile reads a test file and returns its policy paths and cases.
func parseTestFile(data []byte) ([]string, []testCase, error) {
	var f testFile
	if err := yaml.UnmarshalStrict(data, &f); err != nil {
		return nil, nil, err
	}
	if len(f.Tests) == 0 {
		return nil, nil, errors.New("no tests: the file needs a tests list")
	}
	var cases []testCase
	for g, group := range f.Tests {
		at := fmt.Sprintf("tests[%d]", g)
		actor, err := parseActor(group.Actor)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", at, err)
		}
		before := len(cases)
		for _, list := range []struct {
			outcome string
			items   []expectation
		}{{outcomeAllow, group.Allow}, {outcomeDeny, group.Deny}, {outcomeAudit, group.Audit}} {
			for i, e := range list.items {
				id := fmt.Sprintf("%s.%s[%d]", at, list.outcome, i)
				method, url, _ := strings.Cut(strings.TrimSpace(e.Request), " ")
				req, err := parseURL(method, strings.TrimSpace(url))
				if err != nil {
					return nil, nil, fmt.Errorf("%s: request %q is not \"<METHOD> <URL>\": %w", id, e.Request, err)
				}
				if e.Reason != "" && !slices.Contains(reasons[list.outcome], policy.Reason(e.Reason)) {
					return nil, nil, fmt.Errorf("%s: reason %q is not one a request under %q can have (%s)",
						id, e.Reason, list.outcome, joinReasons(reasons[list.outcome]))
				}
				cases = append(cases, testCase{
					ID: id, Group: group.Name, Actor: actor, Request: method + " " + strings.TrimSpace(url), request: req,
					Want: decision{Decision: list.outcome, Reason: e.Reason, Policy: e.Policy, Template: e.Template},
				})
			}
		}
		if len(cases) == before {
			return nil, nil, fmt.Errorf("%s: no requests under allow, deny or audit", at)
		}
	}
	// "-" reads stdin with -f, but a test file's policies are files: reading
	// stdin for it would make the file mean something else on every run.
	if i := slices.Index(f.Policies, "-"); i >= 0 {
		return nil, nil, fmt.Errorf("policies[%d]: \"-\" (stdin) can only be given with -f", i)
	}
	return f.Policies, cases, nil
}

func joinReasons(rs []policy.Reason) string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = string(r)
	}
	return strings.Join(out, ", ")
}
