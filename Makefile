.PHONY: build test run clean

# Default target
all: build

# Build the CryptoScan binary
build:
	go build -o cryptoscan

# Run the application
run:
	./cryptoscan

# Run all tests
test:
	go test ./...

# Run tests with verbose output
test-v:
	go test -v ./...

# Run specific package tests
test-scanner:
	go test ./internal/scanner

test-git:
	go test ./internal/git

test-reporter:
	go test ./internal/reporter

test-utils:
	go test ./pkg/utils

test-spinner:
	go test ./pkg/spinner

# Clean build artifacts
clean:
	rm -f cryptoscan
	go clean

# Install dependencies
deps:
	go mod tidy

# Build and run with a single command
dev: build run