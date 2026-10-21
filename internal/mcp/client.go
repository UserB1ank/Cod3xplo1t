package mcp

import (
	"context"
	"io"
	"log/slog"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

// NewInMemoryClient connects a real MCP client session to the same server and
// domain handlers that the stdio surface uses. The project supervisor never
// reimplements a tool: it lists and calls the SDK server.
func NewInMemoryClient(ctx context.Context, svc *graph.Service, store storage.FullStore) (*sdk.ClientSession, error) {
	server := NewServer(svc, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	serverTransport, clientTransport := sdk.NewInMemoryTransports()
	go func() {
		_, _ = server.Connect(ctx, serverTransport, nil)
	}()
	client := sdk.NewClient(&sdk.Implementation{Name: "codexploit-project-supervisor", Version: "1.0.0"}, nil)
	return client.Connect(ctx, clientTransport, nil)
}
