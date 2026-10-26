GO ?= go
PKG := ./...
TEST_FLAGS := -count=1 -shuffle=on -race -timeout 240s
# Staticcheck is pinned: a new release may add checks and turn a green tree red.
STATICCHECK_VERSION ?= v0.8.2

.PHONY: package-joern package-joern-linux test-joern help run down logs build build-web build-scanner build-backend test-web check-contracts docker-build docker-up postgres-up postgres-down postgres-status postgres-logs test test-stress bench-agent bench-corpus bench-eval bench-runtime bench-tools lint fmt-check vet staticcheck fmt tidy clean run-server run-cli run-mcp

help:
	@echo "make build        # build Web UI into bin/server, bin/cli, bin/mcp and the scanner package"
	@echo "make build-scanner # build the pinned process scanner package under bin/plugin-packages"
	@echo "make package-joern # build a pinned native Joern multilingual taint plugin bundle"
	@echo "make package-joern-linux # export a Linux Joern bundle with Docker"
	@echo "make build-web    # install locked frontend dependencies and build assets"
	@echo "make test-web     # frontend domain and API tests"
	@echo "make check-contracts # validate offline interface schemas and examples"
	@echo "make run          # default deployment: application + PostgreSQL at http://127.0.0.1:18085"
	@echo "make down         # stop whichever stack is running"
	@echo "make logs         # follow the default deployment logs"
	@echo "make docker-up    # build and launch the persistent single-container service"
	@echo "make postgres-up  # one-click PostgreSQL deployment (generates secrets outside the repo)"
	@echo "make postgres-down # stop PostgreSQL but keep its data volumes"
	@echo "make postgres-status # show PostgreSQL containers and URL"
	@echo "make postgres-logs # follow PostgreSQL application logs"
	@echo "make test         # go test ./... -count=1 -shuffle=on -race -timeout 240s (same as CI)"
	@echo "make test-stress  # repeat the suite to catch filesystem/lifecycle races"
	@echo "make bench-agent  # replay the golden agent scenarios and write dist/agent-baseline.json"
	@echo "make lint         # fmt-check + vet + staticcheck (same as the CI lint job)"
	@echo "make fmt-check    # gofmt over every tracked Go file"
	@echo "make vet staticcheck fmt tidy"
	@echo "make run-server   # start the REST API on :8080"
	@echo "make run-mcp      # serve the graph over MCP on stdio"
	@echo "make run-cli ARGS=\"scan --source /path/to/repo\""

build: build-web build-scanner build-plugin-tools
	$(GO) build -trimpath -tags embedui -o bin/server ./cmd/server
	$(GO) build -trimpath -o bin/cli ./cmd/cli
	$(GO) build -trimpath -o bin/mcp ./cmd/mcp

build-scanner:
	@mkdir -p "bin/plugin-packages/codexploit.static-patterns@1.0.15"
	$(GO) build -trimpath -buildvcs=false -o "bin/plugin-packages/codexploit.static-patterns@1.0.15/scanner" ./cmd/scanner
	@cp internal/scanner/manifest.json "bin/plugin-packages/codexploit.static-patterns@1.0.15/manifest.json"
	@chmod 0755 "bin/plugin-packages/codexploit.static-patterns@1.0.15/scanner"
	@chmod 0644 "bin/plugin-packages/codexploit.static-patterns@1.0.15/manifest.json"

build-web:
	npm --prefix web ci --no-audit --no-fund
	npm --prefix web run build

build-backend:
	$(GO) build -trimpath -o bin/server ./cmd/server
	$(GO) build -trimpath -o bin/cli ./cmd/cli
	$(GO) build -trimpath -o bin/mcp ./cmd/mcp

test-web:
	npm --prefix web test

package-joern-linux:
	docker build --file plugins/joern/Dockerfile --output type=local,dest=bin/joern-linux .

package-joern:
	python3 scripts/package-joern.py

# Requires a real offline bundle; no mock CPG is used.
test-joern:
	@test -n "$(JOERN_TEST_PACKAGE)" || (echo "Set JOERN_TEST_PACKAGE to the offline package"; exit 1)
	JOERN_TEST_PACKAGE="$(JOERN_TEST_PACKAGE)" $(GO) test ./cmd/joern-adapter -race -count=1

build-plugin-tools:
	$(GO) build -trimpath -o bin/pluginpack ./cmd/pluginpack
	$(GO) build -trimpath -o bin/plugin-adapter ./cmd/plugin-adapter

check-contracts:
	$(GO) test ./contracts/... -count=1

# Default deployment: application + PostgreSQL. Secrets are generated into a
# Docker volume on first start; nothing secret lives in the repository.
run:
	docker compose up -d --build --wait
	@echo "Codexploit (PostgreSQL) is running at http://127.0.0.1:$${CODEXPLOIT_PORT:-18085}"

down:
	-docker compose down

logs:
	docker compose logs -f

docker-build:
	docker compose build

docker-up:
	docker compose up -d --build

# One-click PostgreSQL deployment. Secrets are generated outside the repository
# and reused on later runs. Override the optional source mount with
# SOURCE_ROOT=/absolute/path or CODEXPLOIT_SOURCE_ROOT.
postgres-up:
	./scripts/deploy-postgres.sh up "$(SOURCE_ROOT)"

postgres-down:
	./scripts/deploy-postgres.sh down

postgres-status:
	./scripts/deploy-postgres.sh status

postgres-logs:
	./scripts/deploy-postgres.sh logs

test:
	$(GO) test $(PKG) $(TEST_FLAGS)

# Real PostgreSQL in a fresh isolated Compose project; credentials are temporary.
.PHONY: pi-worker
pi-worker:
	cd runtime/pi-worker && npm ci --no-audit --no-fund && npm run build && node --test test/*.test.mjs

.PHONY: test-postgres
test-postgres:
	python3 scripts/test-postgres.py

# The race detector cannot see filesystem and lifecycle races; repeat the suite
# on a dirty machine instead.
test-stress:
	$(GO) test $(PKG) $(TEST_FLAGS) -count=3

# Stop-quality baseline: the golden scenarios replay without a model, so the same
# script always produces the same counters. The summary is machine readable and is
# what later loop changes are compared against.
bench-corpus:
	go run ./cmd/bench-corpus $(BENCH_CORPUS_ARGS)

bench-eval:
	go run ./cmd/bench-eval $(BENCH_EVAL_ARGS)

bench-runtime:
	go run ./cmd/bench-runtime $(BENCH_ARGS)

bench-tools:
	go run ./cmd/bench-tools $(BENCH_TOOLS_ARGS)

bench-agent:
	@mkdir -p dist
	AGENT_BENCH_OUT=$(CURDIR)/dist/agent-baseline.json $(GO) test ./internal/agent -run TestGoldenBaseline -count=1 -v

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
