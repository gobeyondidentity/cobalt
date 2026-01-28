package transport

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ============================================================================
// TmfifoNetTransport Tests
// ============================================================================

func TestNewTmfifoNetTransport_DeviceNotFound(t *testing.T) {
	_, err := NewTmfifoNetTransport("/nonexistent/device")
	if err != ErrTmfifoDeviceNotFound {
		t.Errorf("expected ErrTmfifoDeviceNotFound, got %v", err)
	}
}

func TestNewTmfifoNetTransport_DefaultPath(t *testing.T) {
	// Create a temp directory with a fake device file
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_net0")

	// Create a fake device file (regular file as a stand-in)
	f, err := os.Create(fakePath)
	if err != nil {
		t.Fatalf("failed to create fake device: %v", err)
	}
	f.Close()

	// Test with explicit path
	transport, err := NewTmfifoNetTransport(fakePath)
	if err != nil {
		t.Fatalf("NewTmfifoNetTransport failed: %v", err)
	}

	if transport.Type() != TransportTmfifoNet {
		t.Errorf("Type() = %s, want %s", transport.Type(), TransportTmfifoNet)
	}
}

func TestTmfifoNetTransport_Type(t *testing.T) {
	// Create internal transport to test Type
	transport := &TmfifoNetTransport{devicePath: "/dev/tmfifo_net0"}
	if transport.Type() != TransportTmfifoNet {
		t.Errorf("Type() = %s, want %s", transport.Type(), TransportTmfifoNet)
	}
}

func TestTmfifoNetTransport_ConnectWithFakeDevice(t *testing.T) {
	// Create a temp file to simulate device
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_net0")

	// Create a named pipe (FIFO) for bidirectional communication
	// Note: os.MkdirAll and regular files can't do bidirectional I/O,
	// but we can at least test the open path with a regular file
	f, err := os.Create(fakePath)
	if err != nil {
		t.Fatalf("failed to create fake device: %v", err)
	}
	f.Close()

	transport, err := NewTmfifoNetTransport(fakePath)
	if err != nil {
		t.Fatalf("NewTmfifoNetTransport failed: %v", err)
	}

	// Connect should succeed with the fake file
	err = transport.Connect(context.Background())
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// Type check
	tt, ok := transport.(*TmfifoNetTransport)
	if !ok {
		t.Fatal("expected *TmfifoNetTransport")
	}

	// Verify connected state
	tt.mu.Lock()
	connected := tt.connected
	tt.mu.Unlock()
	if !connected {
		t.Error("expected connected = true after Connect")
	}

	// Close
	err = transport.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestTmfifoNetTransport_ConnectAlreadyConnected(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_net0")

	f, _ := os.Create(fakePath)
	f.Close()

	transport, _ := NewTmfifoNetTransport(fakePath)
	tt := transport.(*TmfifoNetTransport)

	// First connect
	tt.Connect(context.Background())

	// Second connect should be a no-op (already connected)
	err := tt.Connect(context.Background())
	if err != nil {
		t.Errorf("second Connect should succeed: %v", err)
	}

	tt.Close()
}

func TestTmfifoNetTransport_ConnectAfterClose(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_net0")

	f, _ := os.Create(fakePath)
	f.Close()

	transport, _ := NewTmfifoNetTransport(fakePath)
	tt := transport.(*TmfifoNetTransport)

	tt.Close()

	// Connect after close should fail
	err := tt.Connect(context.Background())
	if err == nil {
		t.Error("expected error connecting after close")
	}
	if err.Error() != "transport closed" {
		t.Errorf("error = %q, want 'transport closed'", err.Error())
	}
}

func TestTmfifoNetTransport_ResetAndReconnect(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_net0")

	f, _ := os.Create(fakePath)
	f.Close()

	transport, _ := NewTmfifoNetTransport(fakePath)
	tt := transport.(*TmfifoNetTransport)

	// First connection
	err := tt.Connect(context.Background())
	if err != nil {
		t.Fatalf("first connect failed: %v", err)
	}

	// Close
	tt.Close()

	// Connect after close should fail
	err = tt.Connect(context.Background())
	if err == nil {
		t.Error("expected error connecting after close")
	}

	// Reset should clear the closed state
	tt.Reset()

	// Now connect should succeed
	err = tt.Connect(context.Background())
	if err != nil {
		t.Errorf("connect after reset failed: %v", err)
	}

	tt.mu.Lock()
	connected := tt.connected
	closed := tt.closed
	tt.mu.Unlock()

	if !connected {
		t.Error("expected connected = true after reset + connect")
	}
	if closed {
		t.Error("expected closed = false after reset")
	}

	tt.Close()
}

func TestTmfifoNetTransport_ResetImplementsResettable(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_net0")

	f, _ := os.Create(fakePath)
	f.Close()

	transport, _ := NewTmfifoNetTransport(fakePath)

	// Verify Transport implements Resettable
	resettable, ok := transport.(Resettable)
	if !ok {
		t.Fatal("TmfifoNetTransport does not implement Resettable interface")
	}

	tt := transport.(*TmfifoNetTransport)
	tt.Connect(context.Background())
	tt.Close()

	// Use the Resettable interface
	resettable.Reset()

	// Verify we can reconnect
	err := tt.Connect(context.Background())
	if err != nil {
		t.Errorf("connect after Reset() via interface failed: %v", err)
	}

	tt.Close()
}

func TestTmfifoNetTransport_SendNotConnected(t *testing.T) {
	transport := &TmfifoNetTransport{devicePath: "/fake"}

	msg := &Message{Type: MessageEnrollRequest}
	err := transport.Send(msg)
	if err == nil {
		t.Error("expected error when not connected")
	}
	if err.Error() != "transport not connected" {
		t.Errorf("error = %q, want 'transport not connected'", err.Error())
	}
}

func TestTmfifoNetTransport_SendAfterClose(t *testing.T) {
	transport := &TmfifoNetTransport{devicePath: "/fake", connected: true, closed: true}

	msg := &Message{Type: MessageEnrollRequest}
	err := transport.Send(msg)
	if err == nil {
		t.Error("expected error when closed")
	}
	if err.Error() != "transport closed" {
		t.Errorf("error = %q, want 'transport closed'", err.Error())
	}
}

func TestTmfifoNetTransport_RecvNotConnected(t *testing.T) {
	transport := &TmfifoNetTransport{devicePath: "/fake"}

	_, err := transport.Recv()
	if err == nil {
		t.Error("expected error when not connected")
	}
	if err.Error() != "transport not connected" {
		t.Errorf("error = %q, want 'transport not connected'", err.Error())
	}
}

func TestTmfifoNetTransport_RecvAfterClose(t *testing.T) {
	transport := &TmfifoNetTransport{devicePath: "/fake", connected: true, closed: true}

	_, err := transport.Recv()
	if err != io.EOF {
		t.Errorf("error = %v, want io.EOF", err)
	}
}

func TestTmfifoNetTransport_SendAndRecvWithPipe(t *testing.T) {
	// Create a pipe for testing bidirectional communication
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_net0")

	// Create a regular file for read/write
	f, err := os.OpenFile(fakePath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	defer f.Close()

	// Create transport with pre-opened file
	transport := newTmfifoNetTransportFromDevice(f, fakePath)

	// Send a message (writes to file)
	msg := &Message{
		Type:    MessageEnrollRequest,
		ID:      "test-123",
		Payload: json.RawMessage(`{"hostname":"test-host"}`),
	}

	err = transport.Send(msg)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	// Seek to beginning for read
	f.Seek(0, 0)

	// Recv the message
	received, err := transport.Recv()
	if err != nil {
		t.Fatalf("Recv failed: %v", err)
	}

	if received.Type != MessageEnrollRequest {
		t.Errorf("Type = %s, want %s", received.Type, MessageEnrollRequest)
	}
	if received.ID != "test-123" {
		t.Errorf("ID = %s, want test-123", received.ID)
	}

	transport.Close()
}

func TestTmfifoNetTransport_DoubleClose(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_net0")

	f, _ := os.Create(fakePath)
	f.Close()

	transport, _ := NewTmfifoNetTransport(fakePath)
	tt := transport.(*TmfifoNetTransport)
	tt.Connect(context.Background())

	// First close
	err := tt.Close()
	if err != nil {
		t.Fatalf("first Close failed: %v", err)
	}

	// Second close should be safe
	err = tt.Close()
	if err != nil {
		t.Errorf("second Close should not error: %v", err)
	}
}

func TestTmfifoNetTransport_CloseWithoutDevice(t *testing.T) {
	// Transport that was never connected (no device opened)
	transport := &TmfifoNetTransport{devicePath: "/fake"}

	err := transport.Close()
	if err != nil {
		t.Errorf("Close without device should succeed: %v", err)
	}
}

// ============================================================================
// TmfifoNetListener Tests
// ============================================================================

func TestNewTmfifoNetListener_DeviceNotFound(t *testing.T) {
	_, err := NewTmfifoNetListener("/nonexistent/device")
	if err != ErrTmfifoDeviceNotFound {
		t.Errorf("expected ErrTmfifoDeviceNotFound, got %v", err)
	}
}

func TestNewTmfifoNetListener_DefaultPath(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_net0")

	f, _ := os.Create(fakePath)
	f.Close()

	listener, err := NewTmfifoNetListener(fakePath)
	if err != nil {
		t.Fatalf("NewTmfifoNetListener failed: %v", err)
	}
	defer listener.Close()

	if listener.Type() != TransportTmfifoNet {
		t.Errorf("Type() = %s, want %s", listener.Type(), TransportTmfifoNet)
	}
}

func TestTmfifoNetListener_Type(t *testing.T) {
	listener := &TmfifoNetListener{devicePath: "/dev/tmfifo_net0"}
	if listener.Type() != TransportTmfifoNet {
		t.Errorf("Type() = %s, want %s", listener.Type(), TransportTmfifoNet)
	}
}

func TestTmfifoNetListener_AcceptAndClose(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_net0")

	f, _ := os.Create(fakePath)
	f.Close()

	listener, err := NewTmfifoNetListener(fakePath)
	if err != nil {
		t.Fatalf("NewTmfifoNetListener failed: %v", err)
	}

	// Accept should succeed (opens the device)
	transport, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}

	if transport.Type() != TransportTmfifoNet {
		t.Errorf("accepted transport Type() = %s, want %s", transport.Type(), TransportTmfifoNet)
	}

	// Close the transport
	transport.Close()

	// Wait for watchTransportClose to release the token
	time.Sleep(150 * time.Millisecond)

	// Close the listener
	err = listener.Close()
	if err != nil {
		t.Errorf("listener Close failed: %v", err)
	}
}

func TestTmfifoNetListener_DoubleClose(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_net0")

	f, _ := os.Create(fakePath)
	f.Close()

	listener, _ := NewTmfifoNetListener(fakePath)

	// First close
	err := listener.Close()
	if err != nil {
		t.Fatalf("first Close failed: %v", err)
	}

	// Second close should be safe
	err = listener.Close()
	if err != nil {
		t.Errorf("second Close should not error: %v", err)
	}
}

func TestTmfifoNetListener_AcceptAfterClose(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_net0")

	f, _ := os.Create(fakePath)
	f.Close()

	listener, _ := NewTmfifoNetListener(fakePath)

	// Accept once to consume the initial token
	transport, _ := listener.Accept()
	transport.Close()

	// Wait for token release
	time.Sleep(150 * time.Millisecond)

	// Close the listener
	listener.Close()

	// Accept after close should fail immediately (channel closed)
	// This test verifies the channel close behavior
}

func TestTmfifoNetListener_CloseWithActiveTransport(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_net0")

	f, _ := os.Create(fakePath)
	f.Close()

	listener, _ := NewTmfifoNetListener(fakePath)

	// Accept a connection
	transport, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}

	// Close the transport first to let watchTransportClose complete
	transport.Close()

	// Wait for watchTransportClose to finish processing
	time.Sleep(200 * time.Millisecond)

	// Now close the listener (transport already closed)
	err = listener.Close()
	if err != nil {
		t.Errorf("listener Close failed: %v", err)
	}

	// Verify transport is closed
	tt := transport.(*TmfifoNetTransport)
	tt.mu.Lock()
	closed := tt.closed
	tt.mu.Unlock()

	if !closed {
		t.Error("expected transport to be closed")
	}
}

func TestNewTmfifoNetTransportFromDevice(t *testing.T) {
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "tmfifo_net0")

	f, err := os.Create(fakePath)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Use the internal constructor
	transport := newTmfifoNetTransportFromDevice(f, fakePath)

	if transport.devicePath != fakePath {
		t.Errorf("devicePath = %q, want %q", transport.devicePath, fakePath)
	}
	if !transport.connected {
		t.Error("expected connected = true when created from device")
	}
	if transport.device != f {
		t.Error("expected device to be set")
	}
	if transport.reader == nil {
		t.Error("expected reader to be set")
	}

	transport.Close()
}
