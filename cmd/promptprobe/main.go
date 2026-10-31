// Command promptprobe sends adversarial prompts to an AI application and
// reports which attacks succeeded, so a developer can check whether the
// application resists malicious input and catch regressions when its model or
// prompt changes.
//
// This file only handles the command line: it parses flags, picks a
// subcommand, and turns the outcome into an exit code. The actual work lives
// in the internal packages, so it can be tested without running the binary.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/beardedbarista/promptprobe/internal/suite"
)

// version identifies the build in bug reports and saved reports. The Makefile
// replaces "dev" with the git commit at build time (-ldflags "-X
// main.version=..."), so a plain "go build" still prints "dev". It must be a
// var: the linker can rewrite variables but not constants.
var version = "dev"

// Exit codes let CI decide what to do with a run without parsing its output.
// Each number has one meaning and is written only here, so the meaning cannot
// drift between call sites. exitFindings and exitInconclusive are unused until
// the runner can produce results; they are defined now so the numbering is
// settled before anything depends on it. Keep usage() in step with this list.
const (
	exitOK           = 0 // every case passed: the target resisted every attack
	exitFindings     = 1 // at least one attack succeeded: a vulnerability
	exitOperational  = 2 // nothing tested: bad flags or suite, target down
	exitInconclusive = 3 // no attack succeeded, but some need human review
)

// main does nothing except hand the exit code from run to the operating system.
// See run for why the logic is not here.
func main() {
	os.Exit(run(os.Args[1:]))
}

// run dispatches to a subcommand and returns the exit code instead of exiting.
//
// os.Exit ends the process on the spot, so a test that reached it would end
// the test binary too. Keeping every decision in run, which only returns an
// int, lets a test call it with any arguments and check the code it returns.
//
// Running with no arguments is an error (exit 2) so a script that forgets its
// arguments fails visibly. Asking for help is a success (exit 0).
func run(args []string) int {
	if len(args) == 0 {
		usage()
		return exitOperational
	}

	switch args[0] {
	case "run":
		return cmdRun(args[1:])
	case "send":
		return cmdSend(args[1:])
	// Accept the spellings people try first, so no one gets an error for
	// asking for the version or for help.
	case "version", "--version", "-version":
		fmt.Println("promptprobe", version)
		return exitOK
	case "help", "--help", "-h":
		usage()
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "promptprobe: unknown subcommand %q\n\n", args[0])
		usage()
		return exitOperational
	}
}

// cmdRun is the main use of the tool: run every case in a suite against a
// target. Sending prompts is not built yet, so for now it loads and validates
// the suite and lists the cases, which proves the suite file is usable.
func cmdRun(args []string) int {
	// ContinueOnError makes Parse return bad flags as an error. The default,
	// ExitOnError, would call os.Exit inside the flag package and stop run from
	// returning a code a test can check.
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	suitePath := fs.String("suite", "", "path to a JSON test suite (required)")
	// The default URL is where mockllm listens, so the demo needs no flags.
	targetURL := fs.String("target", "http://localhost:8080/v1/chat", "target endpoint")

	// On a parse error the flag package has already printed the error and the
	// flag list to stderr, so printing again would show the message twice.
	if err := fs.Parse(args); err != nil {
		return exitOperational
	}

	// The flag package has no notion of a required flag, so check by hand.
	if *suitePath == "" {
		fmt.Fprintln(os.Stderr, "promptprobe run: --suite is required")
		fs.Usage()
		return exitOperational
	}

	// A suite that will not load means nothing was tested. That is exit 2, not
	// a finding: reporting it as a vulnerability would overstate the results.
	s, err := suite.Load(*suitePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "promptprobe run: %v\n", err)
		return exitOperational
	}

	fmt.Printf("suite %q: %d cases, would run against %s\n\n", s.Name, len(s.Cases), *targetURL)
	printCases(os.Stdout, s.Cases)
	return exitOK
}

// printCases prints one row per case so the user can confirm which cases a
// suite contains before running it. tabwriter pads each column to its widest
// cell, so rows line up however long the IDs and category names are.
//
// It takes an io.Writer rather than writing to os.Stdout directly so a test
// can pass a buffer and check the output.
func printCases(w io.Writer, cases []suite.Case) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tCATEGORY\tSEVERITY\tOWASP\tDETECTOR")
	for _, c := range cases {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", c.ID, c.Category, c.Severity, c.OWASP, c.Detector.Type)
	}
	// tabwriter holds every row until Flush, because it cannot pad a column
	// until it has seen the widest cell. Without Flush nothing is printed.
	tw.Flush()
}

// cmdSend sends one prompt and prints the reply. It exists for trying out an
// attack by hand, or checking that a target is reachable, before adding the
// prompt to a suite. Sending is not built yet, so for now it checks its flags
// and prints what it would send.
func cmdSend(args []string) int {
	// Same flag handling as cmdRun; see the comments there.
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	targetURL := fs.String("target", "http://localhost:8080/v1/chat", "target endpoint")
	prompt := fs.String("prompt", "", "the prompt to send (required)")

	if err := fs.Parse(args); err != nil {
		return exitOperational
	}

	if *prompt == "" {
		fmt.Fprintln(os.Stderr, "promptprobe send: --prompt is required")
		fs.Usage()
		return exitOperational
	}

	fmt.Printf("would send %q to %s\n", *prompt, *targetURL)
	return exitOK
}

// usage prints the command summary to stderr, not stdout. stdout carries only
// results, so "promptprobe run ... > results.txt" captures results without
// help text mixed in, even when usage is printed after an error.
func usage() {
	fmt.Fprint(os.Stderr, `promptprobe — adversarial test runner for AI applications

usage:
  promptprobe run  --suite <path> [--target <url>]
  promptprobe send --prompt <text> [--target <url>]
  promptprobe version

exit codes:
  0  all cases passed, the target resisted
  1  findings: at least one attack succeeded
  2  operational failure, nothing was tested
  3  no failures, but some results need triage
`)
}
