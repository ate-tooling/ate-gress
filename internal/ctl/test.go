package ctl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ate-tooling/ate-gress/internal/lint"
)

// testReport is the result of `ategressctl test`, and its JSON output.
type testReport struct {
	Passed int              `json:"passed"`
	Failed int              `json:"failed"`
	Files  []testFileReport `json:"files"`
}

type testFileReport struct {
	File string `json:"file"`
	// Policies are the paths the policies were read from.
	Policies []string `json:"policies"`
	// InvalidPolicies lists the policies a cluster would not apply. When
	// there are any, no case of the file is run.
	InvalidPolicies []lint.Finding `json:"invalidPolicies"`
	Cases           []caseReport   `json:"cases"`
}

type caseReport struct {
	ID      string   `json:"id"`
	Group   string   `json:"group,omitempty"`
	Actor   string   `json:"actor"`
	Request string   `json:"request"`
	Want    decision `json:"want"`
	Got     decision `json:"got"`
	Passed  bool     `json:"passed"`
	// Mismatches names the fields of Want that Got does not meet.
	Mismatches []string `json:"mismatches,omitempty"`
}

const testHelp = `Runs the cases in each test file through the policies and reports the ones
whose decision is not the expected one.

The policies are the ones the test file names under "policies", relative to
the test file, unless -f is given, which replaces them. If a policy would be
rejected by the API server or by the compiler, the file fails and none of
its cases are run.

Exits 0 if every case passed, 1 if a case failed or a policy is invalid.`

func runTest(args []string, env Env) error {
	c := newFlags(env, "test", "[-f <policies>]... <test file>...", testHelp, nil)
	files, err := c.parse(args)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return errors.New("test: no test file given")
	}

	// Each test file loads its policies afresh, so with "-f -" each one
	// reads the same stdin.
	nextEnv, err := c.replayStdin(env)
	if err != nil {
		return err
	}

	report := testReport{Files: []testFileReport{}}
	ok := true
	for _, file := range files {
		fr, err := runTestFile(file, c, nextEnv())
		if err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		for _, cr := range fr.Cases {
			if cr.Passed {
				report.Passed++
			} else {
				report.Failed++
			}
		}
		ok = ok && len(fr.InvalidPolicies) == 0
		report.Files = append(report.Files, fr)
	}
	ok = ok && report.Failed == 0

	if c.json() {
		if err := writeJSON(env.Stdout, report); err != nil {
			return err
		}
	} else {
		printTestReport(env, report)
	}
	if !ok {
		return errFailed{}
	}
	return nil
}

func runTestFile(file string, c *common, env Env) (testFileReport, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return testFileReport{}, err
	}
	listed, cases, err := parseTestFile(data)
	if err != nil {
		return testFileReport{}, err
	}
	paths := c.policyPaths(listed, filepath.Dir(file))
	if len(paths) == 0 {
		return testFileReport{}, errors.New("no policies: name them under \"policies\" in the test file, or with -f")
	}
	loaded, err := loadPolicies(paths, env.Stdin)
	if err != nil {
		return testFileReport{}, err
	}

	fr := testFileReport{File: file, Policies: paths, InvalidPolicies: loaded.invalid, Cases: []caseReport{}}
	if len(loaded.invalid) > 0 {
		return fr, nil
	}
	fr.InvalidPolicies = []lint.Finding{}
	for _, tc := range cases {
		got, _ := decide(loaded.snap, tc.Actor, tc.request)
		cr := caseReport{ID: tc.ID, Group: tc.Group, Actor: tc.Actor.String(), Request: tc.Request, Want: tc.Want, Got: got}
		for _, f := range []struct{ name, want, got string }{
			{"decision", tc.Want.Decision, got.Decision},
			{"reason", tc.Want.Reason, got.Reason},
			{"policy", tc.Want.Policy, got.Policy},
			{"template", tc.Want.Template, got.Template},
		} {
			// Only the decision is always checked; the rest when the test
			// file states them.
			if f.want != "" && f.want != f.got {
				cr.Mismatches = append(cr.Mismatches, f.name)
			}
		}
		cr.Passed = len(cr.Mismatches) == 0
		fr.Cases = append(fr.Cases, cr)
	}
	return fr, nil
}

func printTestReport(env Env, report testReport) {
	w := env.Stdout
	invalid := 0
	for _, fr := range report.Files {
		fmt.Fprintln(w, fr.File)
		if len(fr.InvalidPolicies) > 0 {
			invalid++
			fmt.Fprintln(w, "  FAIL  not run: a cluster would not apply these policies as written")
			for _, f := range fr.InvalidPolicies {
				fmt.Fprintf(w, "        %s\n", formatFinding(f))
			}
			continue
		}
		group := ""
		for _, cr := range fr.Cases {
			if cr.Group != group {
				group = cr.Group
				if group != "" {
					fmt.Fprintf(w, "  %s\n", group)
				}
			}
			status := "ok  "
			if !cr.Passed {
				status = "FAIL"
			}
			fmt.Fprintf(w, "  %s  %-5s  %s  %s\n", status, cr.Want.Decision, cr.Actor, cr.Request)
			if cr.Passed {
				continue
			}
			fmt.Fprintf(w, "        %s: got %s\n", cr.ID, cr.Got)
			for _, m := range cr.Mismatches {
				want, got := cr.Want.Decision, cr.Got.Decision
				switch m {
				case "reason":
					want, got = cr.Want.Reason, cr.Got.Reason
				case "policy":
					want, got = cr.Want.Policy, cr.Got.Policy
				case "template":
					want, got = cr.Want.Template, cr.Got.Template
				}
				if got == "" {
					got = "none"
				}
				fmt.Fprintf(w, "        want %s %s, got %s\n", m, want, got)
			}
		}
	}
	fmt.Fprintf(w, "\n%d passed, %d failed", report.Passed, report.Failed)
	if invalid > 0 {
		fmt.Fprintf(w, ", %d test file(s) not run", invalid)
	}
	fmt.Fprintln(w)
}
