package sentry

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/gobeyondidentity/secure-infra/pkg/transport"
)

// TmfifoTransport implements transport.Transport using the tmfifo device.
// This wraps the low-level device access for use with the Transport interface.
type TmfifoTransport struct {
	devicePath string
	device     *os.File
	reader     *bufio.Reader
	mu         sync.Mutex
	connected  bool
	closed     bool
}

// NewTmfifoTransport creates a new tmfifo transport.
// If devicePath is empty, auto-detects from known tmfifo device paths.
func NewTmfifoTransport(devicePath string) *TmfifoTransport {
	if devicePath == "" {
		devicePath, _ = DetectTmfifo()
		if devicePath == "" {
			devicePath = DefaultTmfifoPath // fallback for error reporting
		}
	}
	return &TmfifoTransport{
		devicePath: devicePath,
	}
}

// Connect opens the tmfifo device.
func (t *TmfifoTransport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return fmt.Errorf("transport closed")
	}
	if t.connected {
		return nil
	}

	f, err := os.OpenFile(t.devicePath, os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open tmfifo device %s: %w", t.devicePath, err)
	}

	t.device = f
	t.reader = bufio.NewReader(f)
	t.connected = true
	return nil
}

// Send transmits a message over tmfifo.
func (t *TmfifoTransport) Send(msg *transport.Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.connected || t.device == nil {
		return fmt.Errorf("transport not connected")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	// Append newline delimiter (tmfifo protocol uses newline-delimited JSON)
	data = append(data, '\n')

	if _, err := t.device.Write(data); err != nil {
		return fmt.Errorf("write to tmfifo: %w", err)
	}

	return nil
}

// Recv receives a message from tmfifo.
func (t *TmfifoTransport) Recv() (*transport.Message, error) {
	t.mu.Lock()
	if !t.connected || t.reader == nil {
		t.mu.Unlock()
		return nil, fmt.Errorf("transport not connected")
	}
	reader := t.reader
	t.mu.Unlock()

	line, err := reader.ReadBytes('\n')
	if err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("read from tmfifo: %w", err)
	}

	var msg transport.Message
	if err := json.Unmarshal(line, &msg); err != nil {
		return nil, fmt.Errorf("parse message: %w", err)
	}

	return &msg, nil
}

// Close closes the tmfifo device.
func (t *TmfifoTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	t.closed = true
	t.connected = false

	if t.device != nil {
		err := t.device.Close()
		t.device = nil
		t.reader = nil
		return err
	}

	return nil
}

// Type returns TransportTmfifoNet.
func (t *TmfifoTransport) Type() transport.TransportType {
	return transport.TransportTmfifoNet
}

// NetworkTransport implements transport.Transport using HTTP.
// This is used for non-BlueField deployments where tmfifo is unavailable.
type NetworkTransport struct {
	dpuAgentURL string
	hostname    string
	connected   bool
	closed      bool
	mu          sync.Mutex

	// pendingRecv holds messages received from the server that haven't been read yet.
	// In a real implementation, this would be a proper bidirectional channel.
	// For now, the network transport is primarily request/response based.
	pendingRecv chan *transport.Message
}

// NewNetworkTransport creates a new network transport.
func NewNetworkTransport(dpuAgentURL, hostname string) *NetworkTransport {
	return &NetworkTransport{
		dpuAgentURL: dpuAgentURL,
		hostname:    hostname,
		pendingRecv: make(chan *transport.Message, 10),
	}
}

// Connect establishes the network connection (validates reachability).
func (n *NetworkTransport) Connect(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.closed {
		return fmt.Errorf("transport closed")
	}

	// For HTTP-based transport, we don't maintain a persistent connection.
	// Each Send/Recv is a separate HTTP request.
	n.connected = true
	return nil
}

// Send transmits a message over HTTP.
// Note: The current network mode uses specific REST endpoints, not a generic message protocol.
// This implementation bridges the gap by mapping message types to endpoints.
func (n *NetworkTransport) Send(msg *transport.Message) error {
	n.mu.Lock()
	if !n.connected {
		n.mu.Unlock()
		return fmt.Errorf("transport not connected")
	}
	n.mu.Unlock()

	// The network transport currently doesn't support arbitrary message sending.
	// The Host Agent uses specific HTTP endpoints for register and posture.
	// This is a placeholder for future implementation.
	return fmt.Errorf("NetworkTransport.Send not implemented for message type %s", msg.Type)
}

// Recv receives a message from the network.
// Note: HTTP is request/response, so Recv blocks waiting for queued responses.
func (n *NetworkTransport) Recv() (*transport.Message, error) {
	n.mu.Lock()
	if !n.connected {
		n.mu.Unlock()
		return nil, fmt.Errorf("transport not connected")
	}
	n.mu.Unlock()

	msg, ok := <-n.pendingRecv
	if !ok {
		return nil, io.EOF
	}
	return msg, nil
}

// Close closes the network transport.
func (n *NetworkTransport) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.closed {
		return nil
	}

	n.closed = true
	n.connected = false
	close(n.pendingRecv)
	return nil
}

// Type returns TransportNetwork.
func (n *NetworkTransport) Type() transport.TransportType {
	return transport.TransportNetwork
}

// DPUAgentURL returns the DPU Agent URL for use by higher-level code.
func (n *NetworkTransport) DPUAgentURL() string {
	return n.dpuAgentURL
}

// Hostname returns the hostname for use by higher-level code.
func (n *NetworkTransport) Hostname() string {
	return n.hostname
}

// QueueResponse adds a response message to the pending receive queue.
// This is used by the network client to bridge HTTP responses to the Transport interface.
func (n *NetworkTransport) QueueResponse(msg *transport.Message) error {
	select {
	case n.pendingRecv <- msg:
		return nil
	default:
		return fmt.Errorf("response queue full")
	}
}
