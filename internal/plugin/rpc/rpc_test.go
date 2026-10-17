package rpc_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/plugin/rpc"
)

// peerFixture connects two JSON-RPC peers over a real duplex pipe. Both peers
// serve concurrently, so a call in either direction exercises the same framing
// and routing code a subprocess uses.
type peerFixture struct {
	client *rpc.Conn
	server *rpc.Conn
}

func newPeerFixture(t *testing.T, clientHandler, serverHandler rpc.Handler) *peerFixture {
	t.Helper()
	left, right := net.Pipe()
	fixture := &peerFixture{}
	if clientHandler == nil {
		clientHandler = func(context.Context, string, json.RawMessage) (any, *rpc.Error) {
			return nil, &rpc.Error{Code: rpc.MethodNotFound, Message: "method not found"}
		}
	}
	if serverHandler == nil {
		serverHandler = func(context.Context, string, json.RawMessage) (any, *rpc.Error) {
			return nil, &rpc.Error{Code: rpc.MethodNotFound, Message: "method not found"}
		}
	}
	fixture.client = rpc.New(left, left, clientHandler, rpc.Options{})
	fixture.server = rpc.New(right, right, serverHandler, rpc.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = fixture.client.Serve(ctx) }()
	go func() { _ = fixture.server.Serve(ctx) }()
	return fixture
}

func TestPeerCallsMethodAndReceivesNotification(t *testing.T) {
	events := make(chan string, 8)
	fixture := newPeerFixture(t,
		func(_ context.Context, method string, params json.RawMessage) (any, *rpc.Error) {
			if method != "plugin.event" {
				return nil, &rpc.Error{Code: rpc.MethodNotFound, Message: "unexpected method"}
			}
			var event struct {
				Seq int `json:"seq"`
			}
			if json.Unmarshal(params, &event) != nil || event.Seq != 7 {
				return nil, &rpc.Error{Code: rpc.InvalidParams, Message: "bad event"}
			}
			events <- method
			return nil, nil
		},
		func(_ context.Context, method string, params json.RawMessage) (any, *rpc.Error) {
			if method != "plugin.initialize" {
				return nil, &rpc.Error{Code: rpc.MethodNotFound, Message: "unexpected method"}
			}
			var request struct {
				Protocol string `json:"protocol"`
			}
			if json.Unmarshal(params, &request) != nil || request.Protocol != "codexploit/process-plugin/v1" {
				return nil, &rpc.Error{Code: rpc.InvalidParams, Message: "bad handshake"}
			}
			return map[string]any{"selected": "codexploit/process-plugin/v1"}, nil
		})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var response struct {
		Selected string `json:"selected"`
	}
	if err := fixture.client.Call(ctx, "plugin.initialize", map[string]any{"protocol": "codexploit/process-plugin/v1"}, &response); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if response.Selected != "codexploit/process-plugin/v1" {
		t.Fatalf("response = %+v", response)
	}
	if err := fixture.server.Notify("plugin.event", map[string]any{"seq": 7}); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	select {
	case method := <-events:
		if method != "plugin.event" {
			t.Fatalf("event method = %q", method)
		}
	case <-ctx.Done():
		t.Fatal("notification was not delivered")
	}
}

func TestMessageLimitRejectsOversizedLineWithoutWedging(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	server := rpc.New(right, right, func(context.Context, string, json.RawMessage) (any, *rpc.Error) {
		return map[string]any{"ok": true}, nil
	}, rpc.Options{MaxMessageBytes: 256})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	// A raw caller writes a valid frame whose total line is over the limit.
	raw, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "c-1",
		"method":  "ping",
		"params":  map[string]any{"padding": string(make([]byte, 512))},
	})
	if _, err := left.Write(append(raw, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, rpc.ErrMessageTooLarge) {
			t.Fatalf("Serve error = %v, want ErrMessageTooLarge", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("oversized message did not terminate the peer")
	}
}

func TestMalformedAndUnknownResponsesDoNotHangCallers(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	client := rpc.New(left, left, nil, rpc.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- client.Serve(ctx) }()
	// Send an unknown response id followed by a malformed line.
	if _, err := right.Write([]byte(`{"jsonrpc":"2.0","id":"unknown","result":{}}` + "\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := right.Write([]byte(`not-json` + "\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serveDone:
		if !errors.Is(err, rpc.ErrProtocol) {
			t.Fatalf("Serve error = %v, want ErrProtocol", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("malformed input did not terminate the peer")
	}
}
