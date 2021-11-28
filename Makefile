.ONESHELL:
SHELL := /bin/bash

TEST_PACKAGES = $(shell go list ./... | grep -v "internal/oidctesting" | grep -v "internal/coverage")
TEST_PACKAGES_CSV = $(shell echo -n $(TEST_PACKAGES) | sed "s/ /,/g")

PKGS = $(shell find ./ -name go.mod | sed "s/go.mod//g" | sort)
PKGS_CLEAN = $(shell find ./ -name go.mod | sed "s/go.mod//g" | grep -v "./examples/" | grep -v "./internal/coverage/" | sort)

.PHONY: all
.SILENT: all
all: tidy lint fmt vet test build-examples

.PHONY: lint
.SILENT: lint
lint:
	set -e
	ROOT_DIR=$(PWD)
	for pkg in $(PKGS_CLEAN); do
		(
			echo $$pkg: golangci-lint run 
			cd $$pkg
			golangci-lint run -c $${ROOT_DIR}/.golangci.yaml
		)
	done

.PHONY: fmt
.SILENT: fmt
fmt:
	set -e
	for pkg in $(PKGS); do
		(
			echo $$pkg: go fmt 
			cd $$pkg
			go fmt ./...
		)
	done
	

.PHONY: tidy
.SILENT: tidy
tidy:
	set -e
	for pkg in $(PKGS); do
		(
			echo $$pkg: go mod tidy 
			cd $$pkg
			go mod tidy
		)
	done

.PHONY: vet
.SILENT: vet
vet:
	set -e
	for pkg in $(PKGS); do
		(
			echo $$pkg: go vet
			cd $$pkg
			go vet ./...
		)
	done

.SILENT: test
.PHONY: test
test: fmt vet
	set -e
	for pkg in $(PKGS_CLEAN); do
		(
			echo $$pkg: go test
			cd $$pkg
			go test -timeout 30s -cover ./...
		)
	done

.SILENT: bench
.PHONY: bench
bench:
	set -e
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
	set -e
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
		if [[ $${CI} == "true" ]]; then
			go tool cover -func=$${ROOT_DIR}/tmp/coverage_merged.out
		else
			go tool cover -html=$${ROOT_DIR}/tmp/coverage_merged.out
		fi
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
