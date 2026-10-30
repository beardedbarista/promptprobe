// Command promptprobe runs adversarial test suites against an AI application
// and reports which attacks succeeded.
//
// M0 scope: argument parsing, subcommand dispatch, and exit codes only.
// The subcommands print what they would do; M1 gives "run" a real suite loader.
package main

import (
	"flag"
	"fmt"
	"os"
)

// version is overwritten at build time by the Makefile's -ldflags.
// It has to be a var, not a const: the linker can only patch variables.
var version = "dev"

// Exit codes are part of promptprobe's public interface, not an afterthought.
// CI reads them to decide whether a run found vulnerabilities, so they are
// defined once, here, and never written as bare numbers elsewhere. Spec §5.5.
const (
	exitOK           = 0 // every case passed: the target resisted everything
	exitFindings     = 1 // at least one attack succeeded
	exitOperational  = 2 // could not run: bad suite, unreachable target, bad flags
	exitInconclusive = 3 // no failures, but results need human triage
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run holds everything main would otherwise do, and returns an exit code
// instead of calling os.Exit.
//
// That split is the whole point: os.Exit terminates the process immediately,
// which means any code that calls it cannot be tested. A function returning an
// int can be. main stays one line so that every decision below it is reachable
// from a test.
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

// cmdRun will execute a whole suite against a target. For now it validates its
// flags and reports what it would do.
func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	suitePath := fs.String("suite", "", "path to a JSON test suite (required)")
	targetURL := fs.String("target", "http://localhost:8080/v1/chat", "target endpoint")

	// ContinueOnError makes Parse return an error rather than killing the
	// process, which is what keeps run() testable. The default, ExitOnError,
	// would call os.Exit from inside the flag package and defeat the split above.
	if err := fs.Parse(args); err != nil {
		return exitOperational
	}

	if *suitePath == "" {
		fmt.Fprintln(os.Stderr, "promptprobe run: --suite is required")
		fs.Usage()
		return exitOperational
	}

	fmt.Printf("would run suite %q against %s\n", *suitePath, *targetURL)
	return exitOK
}

// cmdSend sends a single prompt, for manual exploration and debugging.
func cmdSend(args []string) int {
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

// usage goes to stderr because it is printed alongside errors. Help text on
// stdout would get mixed into piped output.
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
