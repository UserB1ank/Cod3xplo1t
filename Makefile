GO ?= go
PKG := ./...
TEST_FLAGS := -count=1 -shuffle=on -race -timeout 240s
# Staticcheck is pinned: a new release may add checks and turn a green tree red.
STATICCHECK_VERSION ?= v0.8.2

.PHONY: help build build-web build-scanner build-backend test-web check-contracts docker-build docker-up test test-stress lint fmt-check vet staticcheck fmt tidy clean run-server run-cli run-mcp

help:
	@echo "make build        # build Web UI into bin/server, bin/cli, bin/mcp and the scanner package"
	@echo "make build-scanner # build the pinned process scanner package under bin/plugin-packages"
	@echo "make build-web    # install locked frontend dependencies and build assets"
	@echo "make test-web     # frontend domain and API tests"
	@echo "make check-contracts # validate offline interface schemas and examples"
	@echo "make docker-up    # build and launch the persistent single-container service"
	@echo "make test         # go test ./... -count=1 -shuffle=on -race -timeout 240s (same as CI)"
	@echo "make test-stress  # repeat the suite to catch filesystem/lifecycle races"
	@echo "make lint         # fmt-check + vet + staticcheck (same as the CI lint job)"
	@echo "make fmt-check    # gofmt over every tracked Go file"
	@echo "make vet staticcheck fmt tidy"
	@echo "make run-server   # start the REST API on :8080"
	@echo "make run-mcp      # serve the graph over MCP on stdio"
	@echo "make run-cli ARGS=\"scan --source /path/to/repo\""

build: build-web build-scanner
	$(GO) build -trimpath -tags embedui -o bin/server ./cmd/server
	$(GO) build -trimpath -o bin/cli ./cmd/cli
	$(GO) build -trimpath -o bin/mcp ./cmd/mcp

build-scanner:
	@mkdir -p "bin/plugin-packages/codexploit.static-patterns@1.0.0"
	$(GO) build -trimpath -o "bin/plugin-packages/codexploit.static-patterns@1.0.0/scanner" ./cmd/scanner
	@cp internal/scanner/manifest.json "bin/plugin-packages/codexploit.static-patterns@1.0.0/manifest.json"
	@chmod 0755 "bin/plugin-packages/codexploit.static-patterns@1.0.0/scanner"
	@chmod 0644 "bin/plugin-packages/codexploit.static-patterns@1.0.0/manifest.json"

build-web:
	npm --prefix web ci --no-audit --no-fund
	npm --prefix web run build

build-backend:
	$(GO) build -trimpath -o bin/server ./cmd/server
	$(GO) build -trimpath -o bin/cli ./cmd/cli
	$(GO) build -trimpath -o bin/mcp ./cmd/mcp

test-web:
	npm --prefix web test

check-contracts:
	$(GO) test ./contracts/v1 -count=1

docker-build:
	docker compose build

docker-up:
	docker compose up -d --build

test:
	$(GO) test $(PKG) $(TEST_FLAGS)

# Real PostgreSQL in a fresh isolated Compose project; credentials are temporary.
.PHONY: test-postgres
test-postgres:
	python3 scripts/test-postgres.py

# The race detector cannot see filesystem and lifecycle races; repeat the suite
# on a dirty machine instead.
test-stress:
	$(GO) test $(PKG) $(TEST_FLAGS) -count=3

# Formatting is a gate, not a formatter: gofmt lists the files that need work and
# exits non-zero on a parse error, which `set -e` turns into a failed target. Only
# tracked files are checked, so a git-ignored .cache/ cannot fail the gate with a
# dependency fixture that is intentionally not parseable.
fmt-check:
	@set -e; \
	unformatted=$$(git ls-files -z -- '*.go' | xargs -0 gofmt -l); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed on:"; echo "$$unformatted"; exit 1; \
	fi

vet:
	$(GO) vet $(PKG)

# Staticcheck runs from its own module at the pinned version, so linting never
# changes this repository's module graph.
staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) $(PKG)

lint: fmt-check vet staticcheck

fmt:
	$(GO) fmt $(PKG)

tidy:
	$(GO) mod tidy

run-server:
	$(GO) run ./cmd/server

run-cli:
	$(GO) run ./cmd/cli $(ARGS)

run-mcp:
	$(GO) run ./cmd/mcp

clean:
	rm -rf bin
