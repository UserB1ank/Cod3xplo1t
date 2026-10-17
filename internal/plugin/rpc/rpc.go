// Package rpc implements the bounded newline-delimited JSON-RPC 2.0 transport
// used between the plugin host and a process plugin. stdout carries one message
// per line; stderr is reserved for bounded diagnostics.
package rpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
)

// DefaultMaxMessageBytes is the control-channel ceiling. Large artifacts use the
// host artifact channel instead of one oversized JSON message.
const DefaultMaxMessageBytes = 1 << 20

// JSON-RPC error codes used by the transport.
const (
	ParseError     = -32700
	InvalidRequest = -32600
	MethodNotFound = -32601
	InvalidParams  = -32602
	InternalError  = -32603
)

var (
	ErrMessageTooLarge = errors.New("rpc: message exceeds the line limit")
	ErrProtocol        = errors.New("rpc: malformed JSON-RPC message")
	ErrClosed          = errors.New("rpc: connection is closed")
)

// Error is a JSON-RPC error object returned by a handler.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("rpc: %s (%d)", e.Message, e.Code)
}

// Handler serves one inbound request. params is the raw JSON value so a handler
// can validate its own schema. A handler that returns an Error writes that
// object back to the caller; a notification has no response.
type Handler func(ctx context.Context, method string, params json.RawMessage) (any, *Error)

// Options configures a peer.
type Options struct {
	MaxMessageBytes int
	// OnNotification is an optional observer used by tests and diagnostics. It
	// never changes routing.
	OnNotification func(method string, params json.RawMessage)
}

type callResult struct {
	result json.RawMessage
	err    *Error
}

type Conn struct {
	reader  *bufio.Reader
	writer  io.Writer
	handler Handler
	options Options

	writeMu sync.Mutex
	idMu    sync.Mutex
	nextID  uint64
	pending map[string]chan callResult

	mu     sync.Mutex
	closed chan struct{}
	err    error
}

// New builds a peer over an arbitrary duplex stream. The caller owns the stream
// and must close it when the peer is no longer needed.
func New(reader io.Reader, writer io.Writer, handler Handler, options Options) *Conn {
	if options.MaxMessageBytes <= 0 {
		options.MaxMessageBytes = DefaultMaxMessageBytes
	}
	if handler == nil {
		handler = func(context.Context, string, json.RawMessage) (any, *Error) {
			return nil, &Error{Code: MethodNotFound, Message: "method not found"}
		}
	}
	return &Conn{
		reader:  bufio.NewReaderSize(reader, 32<<10),
		writer:  writer,
		handler: handler,
		options: options,
		pending: map[string]chan callResult{},
		closed:  make(chan struct{}),
	}
}

type wireMessage struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method,omitempty"`
	Params  json.RawMessage  `json:"params,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *wireError       `json:"error,omitempty"`
}

type wireError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (w *wireError) asError() *Error {
	return &Error{Code: w.Code, Message: w.Message, Data: w.Data}
}

// Serve reads messages until the peer closes, the context is cancelled, or the
// framing contract is violated. Pending calls are released with the same error.
func (c *Conn) Serve(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			c.shutdown(err)
			return err
		}
		line, err := c.readLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				c.shutdown(ErrClosed)
				return ErrClosed
			}
			c.shutdown(err)
			return err
		}
		var message wireMessage
		if err := decodeLine(line, &message); err != nil {
			c.shutdown(err)
			return err
		}
		if message.Method == "" {
			if err := c.routeResponse(message); err != nil {
				c.shutdown(err)
				return err
			}
			continue
		}
		if err := c.handleRequest(ctx, message); err != nil {
			c.shutdown(err)
			return err
		}
	}
}

func decodeLine(line []byte, message *wireMessage) error {
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(message); err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON value", ErrProtocol)
	}
	if message.JSONRPC != "2.0" {
		return fmt.Errorf("%w: jsonrpc must be 2.0", ErrProtocol)
	}
	if message.Method == "" && message.ID == nil {
		return fmt.Errorf("%w: a response needs an id", ErrProtocol)
	}
	if message.Method != "" && message.Result != nil {
		return fmt.Errorf("%w: a request must not carry a result", ErrProtocol)
	}
	if message.Method == "" {
		hasResult, hasError := message.Result != nil, message.Error != nil
		if hasResult == hasError {
			return fmt.Errorf("%w: a response needs exactly one of result or error", ErrProtocol)
		}
	}
	return nil
}

func (c *Conn) readLine() ([]byte, error) {
	line := make([]byte, 0, 4096)
	for {
		fragment, err := c.reader.ReadSlice('\n')
		if len(line)+len(fragment) > c.options.MaxMessageBytes+1 {
			return nil, ErrMessageTooLarge
		}
		line = append(line, fragment...)
		if err == nil {
			// The newline is framing, not part of the message.
			line = line[:len(line)-1]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			if len(line) == 0 {
				return nil, fmt.Errorf("%w: empty line", ErrProtocol)
			}
			return line, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return nil, err
	}
}

func (c *Conn) handleRequest(ctx context.Context, message wireMessage) error {
	id, err := messageID(message.ID)
	if err != nil {
		return err
	}
	if id == "" {
		// Notifications are processed in arrival order. Events and report chunks
		// depend on this: a later status response must observe every earlier
		// notification, not race it in a fresh goroutine.
		if c.options.OnNotification != nil {
			c.options.OnNotification(message.Method, message.Params)
		}
		_, _ = c.handler(ctx, message.Method, message.Params)
		return nil
	}
	go func() {
		result, rpcErr := c.handler(ctx, message.Method, message.Params)
		response := map[string]any{"jsonrpc": "2.0", "id": id}
		if rpcErr != nil {
			response["error"] = rpcErr
		} else {
			response["result"] = result
		}
		if err := c.write(response); err != nil {
			c.shutdown(err)
		}
	}()
	return nil
}

func (c *Conn) routeResponse(message wireMessage) error {
	id, err := messageID(message.ID)
	if err != nil {
		return err
	}
	c.idMu.Lock()
	waiter, ok := c.pending[id]
	if ok {
		delete(c.pending, id)
	}
	c.idMu.Unlock()
	if !ok {
		// A response nobody is waiting for is not fatal, but it must not be
		// mistaken for a request either.
		return nil
	}
	if message.Error != nil {
		waiter <- callResult{err: message.Error.asError()}
		return nil
	}
	waiter <- callResult{result: message.Result}
	return nil
}

func messageID(raw *json.RawMessage) (string, error) {
	if raw == nil {
		return "", nil
	}
	var id string
	if err := json.Unmarshal(*raw, &id); err != nil || id == "" {
		return "", fmt.Errorf("%w: ids must be non-empty strings", ErrProtocol)
	}
	return id, nil
}

// Call sends one request and waits for its matching response.
func (c *Conn) Call(ctx context.Context, method string, params, result any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	rawParams, err := marshalOptional(params)
	if err != nil {
		return err
	}
	c.idMu.Lock()
	c.nextID++
	id := "c-" + strconv.FormatUint(c.nextID, 10)
	waiter := make(chan callResult, 1)
	c.pending[id] = waiter
	c.idMu.Unlock()

	request := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if rawParams != nil {
		request["params"] = rawParams
	}
	if err := c.write(request); err != nil {
		c.removePending(id)
		return err
	}
	select {
	case response := <-waiter:
		if response.err != nil {
			return response.err
		}
		if result == nil {
			return nil
		}
		if len(response.result) == 0 {
			return fmt.Errorf("%w: response has no result", ErrProtocol)
		}
		if err := json.Unmarshal(response.result, result); err != nil {
			return fmt.Errorf("%w: %v", ErrProtocol, err)
		}
		return nil
	case <-ctx.Done():
		c.removePending(id)
		return ctx.Err()
	case <-c.closed:
		c.removePending(id)
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.err != nil {
			return c.err
		}
		return ErrClosed
	}
}

// Notify sends a notification. It never waits for a reply.
func (c *Conn) Notify(method string, params any) error {
	rawParams, err := marshalOptional(params)
	if err != nil {
		return err
	}
	message := map[string]any{"jsonrpc": "2.0", "method": method}
	if rawParams != nil {
		message["params"] = rawParams
	}
	return c.write(message)
}

func marshalOptional(value any) (json.RawMessage, error) {
	if value == nil {
		return nil, nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func (c *Conn) write(message any) error {
	raw, err := json.Marshal(message)
	if err != nil {
		return err
	}
	if len(raw) > c.options.MaxMessageBytes {
		return ErrMessageTooLarge
	}
	raw = append(raw, '\n')
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	select {
	case <-c.closed:
		return ErrClosed
	default:
	}
	_, err = c.writer.Write(raw)
	return err
}

func (c *Conn) removePending(id string) {
	c.idMu.Lock()
	delete(c.pending, id)
	c.idMu.Unlock()
}

func (c *Conn) shutdown(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
		close(c.closed)
	}
	c.mu.Unlock()
}

// Err returns the error that ended the peer, if any.
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Close releases the peer. A Serve blocked on the underlying reader returns
// ErrClosed once the stream itself is closed by its owner.
func (c *Conn) Close() error {
	c.shutdown(ErrClosed)
	return nil
}
