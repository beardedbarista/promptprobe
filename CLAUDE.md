# CLAUDE.md

Instructions for AI assistants working in this repository.

## Working agreement — read this first

**Josh writes the implementation. You explain, review, and verify.**

This project exists so he builds Go fluency, and success criterion #1 is that he
can explain every line without notes. Handing him finished code defeats the
entire point: reading working code produces recognition, not fluency, and
recognition collapses under interview questioning.

So, for each milestone:

- Explain the Go concept at issue, with a small example that is **not** the
  milestone's own code.
- Restate the acceptance criteria concretely, as commands he can run.
- Wait for him to write it, then review — correctness first, then idiom.
- Flag design decisions as decisions, with a recommendation and reasoning,
  rather than silently choosing for him.

If he explicitly asks you to write implementation code, say once that it trades
against criterion #1, then do as he asks. Boilerplate with no learning in it
(scaffolding, Makefiles, JSON fixtures) is fine to write without ceremony.

## What this project is

A Go CLI that runs adversarial test suites against an AI application, judges the
responses, and emits a reproducible security report. Standard library only.

Full design spec in `docs/`. Read it before proposing anything architectural; it
records the rationale for every decision below, and several were argued over and
settled deliberately.

## Domain rules that are easy to get backwards

**Verdict semantics are inverted from ordinary testing.** `pass` means the target
*resisted*. `fail` means the attack *succeeded* and a vulnerability was found. A
detector firing is bad news about the target, not a passing test. Do not
"correct" this logic — if a change makes a detector match produce `pass`, the
change is wrong.

**`inconclusive` is a first-class verdict**, not an error bucket. Target errors,
timeouts, empty responses, and genuinely ambiguous matches land here. Never fold
them into `fail`; overstating findings is the costly direction to be wrong in a
security report.

**The two targets are not interchangeable.** `mockllm` answers "does my tool work
correctly" and is fully deterministic. Ollama answers "is this target vulnerable"
and is not. Do not propose deleting `mockllm` as redundant once Ollama works —
that argument has been made and rejected, and the reasoning is in the spec. It is
the permanent CI regression target.

**`go test ./...` must pass with Ollama stopped.** The test suite never depends on
a running model. Use `net/http/httptest` for HTTP tests.

**Mock data must be transparently fake.** Invented names, `555` phone numbers,
obviously invalid account identifiers. Never generate realistic-looking personal
data for fixtures — this is a public repository.

## Complexity guardrails

These are deliberate and were agreed in the spec. Do not add:

- Any third-party CLI framework. `flag` only, no Cobra, no Viper.
- An interface before a second implementation exists. The project has exactly one
  interface, `Target`, and it is extracted in M4 *after* both implementations
  work. Do not create it earlier.
- Goroutines or channels before the sequential runner works. Concurrency is
  post-MVP.
- A `pkg/` directory, a config file format, YAML, a database, or a plugin system.
- Docker before M8. It is deliberately late; the reasoning is decision D10.

If a task seems to need a new abstraction to finish, the task was scoped wrong.
Say so rather than adding the abstraction.

## Architecture

```
cmd/promptprobe   CLI: flag parsing, subcommand dispatch, exit codes
cmd/mockllm       the deterministic mock target (one file, no packages)
internal/suite    test-case types, loading, validation
internal/target   Target interface, mock and ollama implementations
internal/detect   detector functions and registry
internal/runner   orchestration: suite x target -> results
internal/report   result types, JSON writer, terminal summary
```

Dependency direction is one-way: `cmd -> runner -> {suite, target, detect,
report}`. Among those four there is exactly one permitted import edge, `report`
importing `detect` for the `Verdict` type. Do not introduce others.

Detectors live in a `map[string]DetectorFunc`. Adding one is a function plus a
map entry — not an interface, not a plugin.

## Conventions

- Go 1.27.2. `go.mod` declares it as a floor; see decision D8.
- Wrap errors with `%w` and add the context the current layer has: which case,
  which file, which URL, which model. Errors must name the offending test case ID.
- Never panic on bad input. Malformed suites, unreachable targets, and missing
  models produce a diagnosable message and an exit code.
- Exit codes are named constants in `cmd/promptprobe`, never bare numbers:
  `0` all passed, `1` findings, `2` operational failure, `3` needs triage.
- Severity is declared in the suite data, never computed.
- Table-driven tests, especially in `internal/detect` where the functions are
  pure.

## Commands

```bash
make build     # compile to bin/promptprobe
make test      # go test ./...
make vet       # go vet ./...
make fmt       # gofmt -l -w . (rewrites files)
make fmt-check # fail if any file is not gofmt-clean; never modifies files
make check     # fmt-check, vet, test — run before every commit
```

## Current state

M0 and M1 complete. Next is M2: `cmd/mockllm`, the deterministic target.

Each milestone is its own commit. Verify before claiming anything works — run the
commands and show the output rather than asserting success.
