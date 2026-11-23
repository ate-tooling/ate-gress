// Command ategressctl checks EgressRoutePolicy files without a cluster: it
// runs test cases through them, explains one decision, and lints them. It
// decides with the code ate-gress decides with, so a policy set that passes
// here behaves the same once applied.
//
// It is a separate binary so that the server image carries nothing a server
// does not run.
package main

import (
	"os"

	"github.com/ate-tooling/ate-gress/internal/ctl"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(ctl.Run(os.Args[1:], ctl.Env{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Version: version}))
}
