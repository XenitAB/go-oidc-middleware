.ONESHELL:
SHELL := /bin/bash

TEST_ENV_FILE = tmp/test_env

ifneq (,$(wildcard $(TEST_ENV_FILE)))
    include $(TEST_ENV_FILE)
    export
endif

.PHONY: all
.SILENT: all
all: tidy lint fmt vet staticcheck test build-examples

.PHONY: lint
.SILENT: lint
lint:
	golangci-lint run

.PHONY: fmt
.SILENT: fmt
fmt:
	go fmt ./...

.PHONY: tidy
.SILENT: tidy
tidy:
	go mod tidy

.PHONY: vet
.SILENT: vet
vet:
	go vet ./...

.PHONY: staticcheck
.SILENT: staticcheck
staticcheck:
	go get -u honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck ./...

.SILENT: test
.PHONY: test
test: fmt vet
	go test -timeout 30s ./... -cover

.SILENT: test-race
.PHONY: test-race
test-race: fmt vet staticcheck
	mkdir -p tmp/
	go test -race --coverprofile=tmp/coverage.out --covermode=atomic ./...

.SILENT: bench
.PHONY: bench
bench: fmt vet test
	go test -timeout 4m -run="-" -bench=".*" ./...

.PHONY: cover
.SILENT: cover
cover:
	mkdir -p tmp/
	go test -timeout 1m -coverpkg=./... -coverprofile=tmp/coverage.out ./...
	go tool cover -html=tmp/coverage.out	

.PHONY: build-examples
.SILENT: build-examples
build-examples:
	set -e
	cd examples/
	go mod tidy
	go fmt ./...
	go vet ./...
	echo build-examples: Start	
	EXAMPLES=$$(find -name main.go -type f)
	for EXAMPLE in $${EXAMPLES}; do
		echo build-example: $${EXAMPLE}
		EXECUTABLE_NAME=$$(echo $${EXAMPLE} | sed "s|\./||g" | sed "s|/main.go||g" | sed "s|/|_|g")
		go build -o ../bin/$${EXECUTABLE_NAME} $${EXAMPLE} 
	done

	echo build-examples: Success
