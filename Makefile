.PHONY: all build bench clean cover deflake fmt lint test test-clean test-long

GOENV=GO111MODULE=on
GO=${GOENV} go

COVERAGE_OUT=/tmp/coverage.out
PACKAGE=./...

TEST_CLAUSE= $(if ${TEST}, -run ${TEST})

DOCTOOLS=docker run --rm  -v "$$(pwd)":"$$(pwd)" -w "$$(pwd)" doctools:latest

.PHONY: all
all: githooks test build lint fmt deps docs

.PHONY: build
build:
	${GO} build ./...

.PHONY: bench
bench:
	${GO} test -short -bench=. -test.timeout=0 -run=^noTests ./...

.PHONY: clean
clean:
	${GO} clean -cache -modcache -i -r

.PHONY: cover
cover: ## compute and display test coverage report
	${GO} test -short -coverprofile=${COVERAGE_OUT} ${PACKAGE}
	${GO} tool cover -html=${COVERAGE_OUT}

.PHONY: deps
deps: ## Build dockerized autodoc tools
	@docker build -t doctools:latest .

.PHONY: docs
docs: ## Apply copyright headers and re-build package-level documents
	@${DOCTOOLS} spdx

gen-readme-docs:
	@${DOCTOOLS} gomarkdoc --output '{{.Dir}}/README.md' ./...

.PHONY: deflake
deflake: ## Runs tests many times to detect flakes
	${GO} test -count=1000 -short -timeout 0 ${TEST_CLAUSE} ./...

.PHONY: fmt
fmt:
	${GO} fmt ./...

.PHONY: githooks
githooks:
	git config core.hooksPath .githooks

.PHONY: lint
lint:
	${GO} vet ./...
	golangci-lint run

.PHONY: lint-fix
lint-fix:
	${GO} vet ./...
	golangci-lint run --fix

.PHONY: test
test:
	${GO} test -short ${TEST_CLAUSE} ./...

.PHONY: test-clean
test-clean: ## Clear test cache and force all tests to be rerun
	${GO} clean -testcache && ${GO} test -count=1 -short ${TEST_CLAUSE} ./...

.PHONY: test-long
test-long: ## Runs all tests, including long-running tests
	${GO} test ${TEST_CLAUSE} ./...

.PHONY: run-dkg-bls
run-dkg-bls: ## Runs test of gennaro dkg w/ BLS signature
	${GO} run test/dkg/bls/main.go

.PHONY: run-dkg-ed25519
run-dkg-ed25519: ## Runs test of gennaro dkg w/ ed25519 signature
	${GO} run test/dkg/ed25519/main.go

.PHONY: run-frost-dkg-bls
run-frost-dkg-bls: ## Runs test of frost dkg w/ BLS signature
	${GO} run test/frost_dkg/bls/main.go

.PHONY: run-frost-dkg-ed25519
run-frost-dkg-ed25519: ## Runs test of frost dkg w/ ed25519 signature
	${GO} run test/frost_dkg/ed25519/main.go

.PHONY: run-frost-dkg-ecdsa
run-frost-dkg-ecdsa: ## Runs test of frost dkg w/ ecdsa signature
	${GO} run test/frost_dkg/k256/main.go

.PHONY: run-frost-full
run-frost-full: ## Runs test of frost dkg w/ frost signature
	${GO} run test/frost_dkg/frost/main.go

.PHONY: run-verenc-elgamal
run-verenc-elgamal: ## Runs test of el-gamal verifiable encryption
	${GO} run test/verenc/elgamal/main.go

.PHONY: run-accumulator-ecc
run-accumulator-ecc: ## Runs test of cryptographic accumulator
	${GO} run test/accumulator/ecc/main.go

.PHONY: compare-bench
compare-bench: ## Runs bench on master and the current branch and compares the result
	bash scripts/perf-comp-local
