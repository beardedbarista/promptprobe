package main

import (
	"path/filepath"
	"testing"
)

// TestRunExitCodes is the reason run() returns an int instead of calling
// os.Exit: every exit path is reachable from here.
func TestRunExitCodes(t *testing.T) {
	suites := filepath.Join("..", "..", "testdata", "suites")

	tests := []struct {
		name string
		args []string
		want int
	}{
		{"no arguments", nil, exitOperational},
		{"unknown subcommand", []string{"bogus"}, exitOperational},
		{"version", []string{"--version"}, exitOK},
		{"help", []string{"help"}, exitOK},
		{"run without suite", []string{"run"}, exitOperational},
		{"run with unknown flag", []string{"run", "--nope"}, exitOperational},
		{"run valid suite", []string{"run", "--suite", filepath.Join(suites, "basic.json")}, exitOK},
		{"run malformed suite", []string{"run", "--suite", filepath.Join(suites, "malformed.json")}, exitOperational},
		{"run invalid suite", []string{"run", "--suite", filepath.Join(suites, "invalid.json")}, exitOperational},
		{"run missing suite", []string{"run", "--suite", filepath.Join(suites, "nope.json")}, exitOperational},
		{"send without prompt", []string{"send"}, exitOperational},
		{"send with prompt", []string{"send", "--prompt", "hello"}, exitOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := run(tt.args); got != tt.want {
				t.Errorf("run(%q) = %d, want %d", tt.args, got, tt.want)
			}
		})
	}
}
