package main

import "testing"

func TestDenyLogLimitFlags(t *testing.T) {
	o, err := parseFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if o.denyLogRate != 1 || o.denyLogBurst != 10 {
		t.Errorf("defaults = %v/s, burst %d; want 1/s, burst 10", o.denyLogRate, o.denyLogBurst)
	}

	tests := []struct {
		name string
		args []string
		ok   bool
	}{
		{"fractional rate", []string{"--deny-log-rate=0.2", "--deny-log-burst=1"}, true},
		{"disabled", []string{"--deny-log-rate=0"}, true},
		// A chart that sets rate 0 need not also keep the burst valid.
		{"disabled, with a burst that would be invalid", []string{"--deny-log-rate=0", "--deny-log-burst=0"}, true},
		{"negative rate", []string{"--deny-log-rate=-1"}, false},
		{"NaN rate", []string{"--deny-log-rate=NaN"}, false},
		{"infinite rate", []string{"--deny-log-rate=Inf"}, false},
		{"zero burst", []string{"--deny-log-burst=0"}, false},
		{"negative burst", []string{"--deny-log-burst=-3"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseFlags(tt.args); (err == nil) != tt.ok {
				t.Errorf("parseFlags(%v) error = %v, want ok=%v", tt.args, err, tt.ok)
			}
		})
	}
}
