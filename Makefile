GO ?= go
PKG := ./...
TEST_FLAGS := -count=1 -shuffle=on -race -timeout 240s

.PHONY: help build test test-stress vet fmt tidy clean run-server run-cli run-mcp

help:
	@echo "make build        # build cmd/server, cmd/cli and cmd/mcp into bin/"
	@echo "make test         # go test ./... -count=1 -shuffle=on -race -timeout 240s (same as CI)"
	@echo "make test-stress  # repeat the suite to catch filesystem/lifecycle races"
	@echo "make vet fmt tidy"
	@echo "make run-server   # start the REST API on :8080"
	@echo "make run-mcp      # serve the graph over MCP on stdio"
	@echo "make run-cli ARGS=\"scan --source /path/to/repo\""

build:
	$(GO) build -o bin/server ./cmd/server
	$(GO) build -o bin/cli ./cmd/cli
	$(GO) build -o bin/mcp ./cmd/mcp

test:
	$(GO) test $(PKG) $(TEST_FLAGS)

# The race detector cannot see filesystem and lifecycle races; repeat the suite
# on a dirty machine instead.
test-stress:
	$(GO) test $(PKG) $(TEST_FLAGS) -count=3

vet:
	$(GO) vet $(PKG)

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
