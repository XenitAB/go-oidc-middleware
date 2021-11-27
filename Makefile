.ONESHELL:
SHELL := /bin/bash

TEST_PACKAGES = $(shell go list ./... | grep -v "internal/oidctesting")
TEST_PACKAGES_CSV = $(shell echo -n $(TEST_PACKAGES) | sed "s/ /,/g")

.PHONY: all
.SILENT: all
all: tidy lint fmt vet staticcheck test test-race build-examples

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
	go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck ./...

.SILENT: test
.PHONY: test
test: fmt vet
	go test -timeout 30s -cover $(TEST_PACKAGES)

.SILENT: test-race
.PHONY: test-race
test-race: fmt vet staticcheck
	mkdir -p tmp/
	go test -race --coverprofile=tmp/coverage.out --covermode=atomic $(TEST_PACKAGES)

.SILENT: bench
.PHONY: bench
bench:
	ROOT_DIR=$(PWD)
	mkdir -p $${ROOT_DIR}/tmp/
	echo -n > $${ROOT_DIR}/tmp/bench.txt
	for pkg in $(PKGS_CLEAN); do
		(
			echo $$pkg: go test -bench
			cd $$pkg
			go test -timeout 4m -run="-" -bench=".*" | tee -a $${ROOT_DIR}/tmp/bench.txt
		)
	done

.PHONY: cover
.SILENT: cover
cover:
	ROOT_DIR=$(PWD)
	mkdir -p $${ROOT_DIR}/tmp/
	for pkg in $(PKGS_CLEAN); do
		(
			echo $$pkg: go test -coverprofile
			cd $$pkg
			PKG_NAME=$$(basename $$(pwd))
			if [[ "$${pkg}" == "./" ]]; then
				go test -timeout 1m -coverpkg=$(TEST_PACKAGES_CSV) -coverprofile=$${ROOT_DIR}/tmp/$${PKG_NAME}_coverage.out ./...
			else
				go test -timeout 1m -coverpkg=./... -coverprofile=$${ROOT_DIR}/tmp/$${PKG_NAME}_coverage.out ./...
			fi
		)
	done

	echo "mode: set" > $${ROOT_DIR}/tmp/coverage_merged.out
	COVERAGE_FILES=$$(find $${ROOT_DIR}/tmp/ -name "*_coverage.out")
	for coverage_file in $${COVERAGE_FILES}; do
		tail -n +2 $${coverage_file} >> $${ROOT_DIR}/tmp/coverage_merged.out
	done
	

	(
		cd ./internal/coverage
		go tool cover -html=$${ROOT_DIR}/tmp/coverage_merged.out
	)
	

.PHONY: build-examples
.SILENT: build-examples
build-examples:
	set -e

	cd examples/
	
	go mod tidy
	go fmt ./...
	go vet ./...

	echo build-examples: Start
	
	go build -o ../bin/api ./api
	go build -o ../bin/pkce-cli ./pkce-cli
	
	echo build-examples: Success
