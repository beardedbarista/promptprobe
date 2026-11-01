BINARY  := promptprobe
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build mock test vet fmt fmt-check check clean

## build: compile the CLI and the mock target into bin/
build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/promptprobe
	go build -o bin/mockllm ./cmd/mockllm

## mock: run the deterministic mock target on :8080 (Ctrl-C to stop)
mock:
	go run ./cmd/mockllm

## test: run every test in the module
test:
	go test ./...

## vet: report suspicious constructs the compiler accepts
vet:
	go vet ./...

## fmt: rewrite every file to gofmt's canonical form
fmt:
	gofmt -l -w .

## fmt-check: fail if any file is not gofmt-clean; never modifies files
fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then echo "not gofmt-clean:"; echo "$$unformatted"; exit 1; fi

## check: what you run before every commit, and what CI will run later
check: fmt-check vet test

clean:
	rm -rf bin reports
