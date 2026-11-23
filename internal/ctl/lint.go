package ctl

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/ate-tooling/ate-gress/internal/egresspolicy"
	"github.com/ate-tooling/ate-gress/internal/lint"
	"github.com/ate-tooling/ate-gress/internal/policyfile"
)

// lintReport is the result of `ategressctl lint`, and its JSON output.
type lintReport struct {
	Findings []lint.Finding `json:"findings"`
	// Summary counts the findings of each severity.
	Summary map[lint.Severity]int `json:"summary"`
}

const lintHelp = `Reports mistakes in a policy set that can be found without a request: policies
the API server or the compiler would reject, Audit policies an Enforce policy
overrides, and path templates that add nothing. --list prints every check.

With --egress-policy, also checks the hosts the policies claim against a
Substrate EgressPolicy manifest, the YAML or JSON that "kubectl ate create
egress-policy -f" takes and "kubectl ate get egress-policy -o yaml" prints.
An EgressPolicy belongs to one actor but does not name it: prefix the file
with <atespace>/<name>= to say which, so that only the policies selecting
that actor are checked. Without the prefix, the manifest's
metadata.atespace narrows it if present, and otherwise every policy is
checked.

Exits 1 if there is a finding at or above --fail-on, and 0 otherwise.`

func runLint(args []string, env Env) error {
	c := newFlags(env, "lint", "-f <policies>... [--egress-policy [<atespace>/<name>=]<file>]...", lintHelp)
	var (
		egressFlags stringList
		failOn      string
		list        bool
	)
	c.fs.Var(&egressFlags, "egress-policy", "Substrate EgressPolicy `manifest` to check claimed hosts against, optionally as <atespace>/<name>=<file>; repeatable.")
	c.fs.StringVar(&failOn, "fail-on", "error", "Lowest `severity` that makes the exit code 1: error, warning, info, or never.")
	c.fs.BoolVar(&list, "list", false, "Print the checks and exit.")
	rest, err := c.parse(args)
	if err != nil {
		return err
	}
	if list {
		return printChecks(env, c.json())
	}
	if len(rest) > 0 {
		return fmt.Errorf("lint: unexpected argument %q; policies are given with -f", rest[0])
	}
	threshold, ok := map[string]int{"error": lint.Error.Rank(), "warning": lint.Warning.Rank(), "info": lint.Info.Rank(), "never": 4}[failOn]
	if !ok {
		return fmt.Errorf("lint: --fail-on %q is not error, warning, info or never", failOn)
	}
	if len(c.policies) == 0 {
		return errors.New("lint: -f <policies> is required")
	}
	var egress []lint.EgressPolicy
	for _, arg := range egressFlags {
		e, err := loadEgressPolicy(arg)
		if err != nil {
			return fmt.Errorf("--egress-policy %s: %w", arg, err)
		}
		egress = append(egress, e)
	}
	set, err := policyfile.Load(c.policies, env.Stdin)
	if err != nil {
		return err
	}

	report := lintReport{Findings: lint.Run(set, egress), Summary: map[lint.Severity]int{lint.Error: 0, lint.Warning: 0, lint.Info: 0}}
	failed := false
	for _, f := range report.Findings {
		report.Summary[f.Severity]++
		failed = failed || f.Severity.Rank() >= threshold
	}
	if report.Findings == nil {
		report.Findings = []lint.Finding{}
	}
	if c.json() {
		if err := writeJSON(env.Stdout, report); err != nil {
			return err
		}
	} else {
		for _, f := range report.Findings {
			fmt.Fprintln(env.Stdout, formatFinding(f))
		}
		if len(report.Findings) > 0 {
			fmt.Fprintln(env.Stdout)
		}
		fmt.Fprintf(env.Stdout, "%d policies: %d errors, %d warnings, %d info\n", len(set.Documents),
			report.Summary[lint.Error], report.Summary[lint.Warning], report.Summary[lint.Info])
	}
	if failed {
		return errFailed{}
	}
	return nil
}

// loadEgressPolicy reads an --egress-policy argument: a manifest path,
// optionally prefixed with the actor the policy belongs to.
func loadEgressPolicy(arg string) (lint.EgressPolicy, error) {
	e := lint.EgressPolicy{File: arg}
	// An existing file wins, so that a path with "=" in it still works.
	if _, err := os.Stat(arg); err != nil {
		if prefix, file, ok := strings.Cut(arg, "="); ok {
			actor, err := parseActor(prefix)
			if err != nil {
				return e, err
			}
			e.File, e.Actor = file, &actor
		}
	}
	data, err := os.ReadFile(e.File)
	if err != nil {
		return e, err
	}
	if e.Policy, err = egresspolicy.Parse(data); err != nil {
		return e, err
	}
	if e.Actor != nil && e.Policy.Atespace != "" && e.Policy.Atespace != e.Actor.Atespace {
		return e, fmt.Errorf("the manifest's metadata.atespace is %q, not the atespace of actor %s", e.Policy.Atespace, e.Actor)
	}
	return e, nil
}

func printChecks(env Env, asJSON bool) error {
	if asJSON {
		type check struct {
			Code     string        `json:"code"`
			Name     string        `json:"name"`
			Severity lint.Severity `json:"severity"`
			Summary  string        `json:"summary"`
		}
		out := make([]check, len(lint.Checks))
		for i, c := range lint.Checks {
			out[i] = check{c.Code, c.Name, c.Severity, c.Summary}
		}
		return writeJSON(env.Stdout, out)
	}
	w := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	for _, c := range lint.Checks {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", c.Code, c.Name, c.Severity, c.Summary)
	}
	return w.Flush()
}
