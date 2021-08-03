SHELL := /bin/bash

TEST_ENV_FILE = tmp/test_env

ifneq (,$(wildcard $(TEST_ENV_FILE)))
    include $(TEST_ENV_FILE)
    export
endif

.PHONY: all
.SILENT: all
all: tidy lint fmt vet gosec test build

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

.SILENT: test
.PHONY: test
test: fmt vet
	go test -timeout 1m ./... -cover

.PHONY: gosec
.SILENT: gosec
gosec:
	gosec ./...

.PHONY: cover
.SILENT: cover
cover:
	go test -timeout 1m -coverpkg=./... -coverprofile=tmp/coverage.out ./...
	go tool cover -html=tmp/coverage.out	

.PHONY: build
.SILENT: build
build:
	go build -ldflags "-w -s -X main.Version=$(VERSION) -X main.Revision=$(REVISION) -X main.Created=$(CREATED)" -o bin/mqtt-log-stdout cmd/mqtt-log-stdout/main.go

