//go:build !windows

package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// testSocketPath generates a short socket path in /tmp to avoid the Unix socket path limit (108 chars).
func testSocketPath(suffix string) string {
	return fmt.Sprintf("/tmp/tmfifo_%d_%s.sock", os.Getpid(), suffix)
}

// ============================================================================
// TmfifoNetTransport Tests
// ============================================================================

func TestNewTmfifoNetTransport_DefaultAddr(t *testing.T) {
	t.Log("Testing NewTmfifoNetTransport uses default DPU address when empty string provided")
	transport, err := NewTmfifoNetTransport("")
	if err != nil {
		t.Fatalf("NewTmfifoNetTransport failed: %v", err)
	}

	tt := transport.(*TmfifoNetTransport)
	if tt.dpuAddr != TmfifoDefaultDPUAddr {
		t.Errorf("dpuAddr = %s, want %s", tt.dpuAddr, TmfifoDefaultDPUAddr)
	}

	if transport.Type() != TransportTmfifoNet {
		t.Errorf("Type() = %s, want %s", transport.Type(), TransportTmfifoNet)
	}
}

func TestNewTmfifoNetTransport_CustomAddr(t *testing.T) {
	t.Log("Testing NewTmfifoNetTransport uses custom address when provided")
	customAddr := "10.0.0.1:8080"
	transport, err := NewTmfifoNetTransport(customAddr)
	if err != nil {
		t.Fatalf("NewTmfifoNetTransport failed: %v", err)
	}

	tt := transport.(*TmfifoNetTransport)
	if tt.dpuAddr != customAddr {
		t.Errorf("dpuAddr = %s, want %s", tt.dpuAddr, customAddr)
	}
}

func TestTmfifoNetTransport_Type(t *testing.T) {
	t.Log("Testing TmfifoNetTransport.Type() returns TransportTmfifoNet")
	transport := &TmfifoNetTransport{dpuAddr: "192.168.100.2:9444"}
	if transport.Type() != TransportTmfifoNet {
		t.Errorf("Type() = %s, want %s", transport.Type(), TransportTmfifoNet)
	}
}

func TestTmfifoNetTransport_ConnectWithUnixSocket(t *testing.T) {
	t.Log("Testing TmfifoNetTransport connects via Unix socket")
	socketPath := testSocketPath("conn")
	t.Cleanup(func() { os.Remove(socketPath) })

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create Unix socket listener: %v", err)
	}
	defer listener.Close()

	// Create transport with socket path
	transport, err := NewTmfifoNetTransportWithSocket("", socketPath)
	if err != nil {
		t.Fatalf("NewTmfifoNetTransportWithSocket failed: %v", err)
	}

	tt := transport.(*TmfifoNetTransport)
	if !tt.useUnixSocket {
		t.Error("expected useUnixSocket = true")
	}

	// Connect should succeed
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Accept connection in goroutine
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	err = transport.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	tt.mu.Lock()
	connected := tt.connected
	tt.mu.Unlock()
	if !connected {
		t.Error("expected connected = true after Connect")
	}

	transport.Close()
	<-done
}

func TestTmfifoNetTransport_ConnectWithTCP(t *testing.T) {
	t.Log("Testing TmfifoNetTransport connects via TCP")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create TCP listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	// Create transport with TCP address
	transport, err := NewTmfifoNetTransport(addr)
	if err != nil {
		t.Fatalf("NewTmfifoNetTransport failed: %v", err)
	}

	tt := transport.(*TmfifoNetTransport)
	if tt.useUnixSocket {
		t.Error("expected useUnixSocket = false for TCP")
	}

	// Accept connection in goroutine
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = transport.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	tt.mu.Lock()
	connected := tt.connected
	tt.mu.Unlock()
	if !connected {
		t.Error("expected connected = true after Connect")
	}

	transport.Close()
	<-done
}

func TestTmfifoNetTransport_ConnectAlreadyConnected(t *testing.T) {
	t.Log("Testing TmfifoNetTransport Connect is idempotent when already connected")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	transport, _ := NewTmfifoNetTransport(addr)
	tt := transport.(*TmfifoNetTransport)

	// Accept in background
	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			defer conn.Close()
			time.Sleep(2 * time.Second)
		}
	}()

	ctx := context.Background()

	// First connect
	tt.Connect(ctx)

	// Second connect should be a no-op
	err = tt.Connect(ctx)
	if err != nil {
		t.Errorf("second Connect should succeed: %v", err)
	}

	tt.Close()
}

func TestTmfifoNetTransport_ConnectAfterClose(t *testing.T) {
	t.Log("Testing TmfifoNetTransport can reconnect after Close")
	transport, _ := NewTmfifoNetTransport("192.168.100.2:9444")
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
	t.Log("Testing TmfifoNetTransport Reset clears closed state and allows reconnection")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	transport, _ := NewTmfifoNetTransport(addr)
	tt := transport.(*TmfifoNetTransport)

	// Accept connections in background
	connCh := make(chan net.Conn, 2)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connCh <- conn
		}
	}()

	ctx := context.Background()

	// First connection
	err = tt.Connect(ctx)
	if err != nil {
		t.Fatalf("first connect failed: %v", err)
	}
	conn1 := <-connCh

	// Close
	tt.Close()
	conn1.Close()

	// Connect after close should fail
	err = tt.Connect(ctx)
	if err == nil {
		t.Error("expected error connecting after close")
	}

	// Reset should clear the closed state
	tt.Reset()

	// Now connect should succeed
	err = tt.Connect(ctx)
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
	t.Log("Testing TmfifoNetTransport implements Resettable interface")
	transport, _ := NewTmfifoNetTransport("")
	_, ok := transport.(Resettable)
	if !ok {
		t.Fatal("TmfifoNetTransport does not implement Resettable interface")
	}
}

func TestTmfifoNetTransport_SendNotConnected(t *testing.T) {
	t.Log("Testing TmfifoNetTransport Send returns error when not connected")
	transport := &TmfifoNetTransport{dpuAddr: "192.168.100.2:9444"}

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
	t.Log("Testing TmfifoNetTransport Send returns error when closed")
	transport := &TmfifoNetTransport{dpuAddr: "192.168.100.2:9444", connected: true, closed: true}

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
	t.Log("Testing TmfifoNetTransport Recv returns error when not connected")
	transport := &TmfifoNetTransport{dpuAddr: "192.168.100.2:9444"}

	_, err := transport.Recv()
	if err == nil {
		t.Error("expected error when not connected")
	}
	if err.Error() != "transport not connected" {
		t.Errorf("error = %q, want 'transport not connected'", err.Error())
	}
}

func TestTmfifoNetTransport_RecvAfterClose(t *testing.T) {
	t.Log("Testing TmfifoNetTransport Recv returns EOF when closed")
	transport := &TmfifoNetTransport{dpuAddr: "192.168.100.2:9444", connected: true, closed: true}

	_, err := transport.Recv()
	if err != io.EOF {
		t.Errorf("error = %v, want io.EOF", err)
	}
}

func TestTmfifoNetTransport_SendAndRecvWithTCP(t *testing.T) {
	t.Log("Testing TmfifoNetTransport Send and Recv with TCP connection")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	clientTransport, _ := NewTmfifoNetTransport(addr)

	// Accept in background
	serverConnCh := make(chan net.Conn)
	go func() {
		conn, _ := listener.Accept()
		serverConnCh <- conn
	}()

	ctx := context.Background()
	err = clientTransport.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	serverConn := <-serverConnCh
	serverTransport := newTmfifoNetTransportFromConn(serverConn)

	// Send a message from client
	msg := &Message{
		Type:    MessageEnrollRequest,
		ID:      "test-123",
		Payload: json.RawMessage(`{"hostname":"test-host"}`),
	}

	err = clientTransport.Send(msg)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	// Receive on server
	received, err := serverTransport.Recv()
	if err != nil {
		t.Fatalf("Recv failed: %v", err)
	}

	if received.Type != MessageEnrollRequest {
		t.Errorf("Type = %s, want %s", received.Type, MessageEnrollRequest)
	}
	if received.ID != "test-123" {
		t.Errorf("ID = %s, want test-123", received.ID)
	}

	clientTransport.Close()
	serverTransport.Close()
}

func TestTmfifoNetTransport_DoubleClose(t *testing.T) {
	t.Log("Testing TmfifoNetTransport Close is safe to call twice")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	transport, _ := NewTmfifoNetTransport(addr)

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	transport.(*TmfifoNetTransport).Connect(context.Background())

	// First close
	err = transport.Close()
	if err != nil {
		t.Fatalf("first Close failed: %v", err)
	}

	// Second close should be safe
	err = transport.Close()
	if err != nil {
		t.Errorf("second Close should not error: %v", err)
	}
}

func TestTmfifoNetTransport_CloseWithoutConnection(t *testing.T) {
	t.Log("Testing TmfifoNetTransport Close succeeds without prior connection")
	transport := &TmfifoNetTransport{dpuAddr: "192.168.100.2:9444"}

	err := transport.Close()
	if err != nil {
		t.Errorf("Close without connection should succeed: %v", err)
	}
}

// ============================================================================
// TmfifoNetListener Tests
// ============================================================================

func TestNewTmfifoNetListener_DefaultAddr(t *testing.T) {
	t.Log("Testing NewTmfifoNetListener uses default address :9444 when empty string provided")
	listener, err := NewTmfifoNetListener("")
	if err != nil {
		// Skip if port is already in use (e.g., on self-hosted runners with aegis)
		if strings.Contains(err.Error(), "address already in use") {
			t.Skip("Default port 9444 in use; skipping")
		}
		t.Fatalf("NewTmfifoNetListener failed: %v", err)
	}
	defer listener.Close()

	if listener.Type() != TransportTmfifoNet {
		t.Errorf("Type() = %s, want %s", listener.Type(), TransportTmfifoNet)
	}
}

func TestTmfifoNetListener_CustomAddr(t *testing.T) {
	t.Log("Testing NewTmfifoNetListener uses custom address when provided")
	listener, err := NewTmfifoNetListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewTmfifoNetListener failed: %v", err)
	}
	defer listener.Close()

	if listener.Type() != TransportTmfifoNet {
		t.Errorf("Type() = %s, want %s", listener.Type(), TransportTmfifoNet)
	}
}

func TestTmfifoNetListener_Type(t *testing.T) {
	t.Log("Testing TmfifoNetListener.Type() returns TransportTmfifoNet")
	listener := &TmfifoNetListener{listenAddr: ":9444"}
	if listener.Type() != TransportTmfifoNet {
		t.Errorf("Type() = %s, want %s", listener.Type(), TransportTmfifoNet)
	}
}

func TestTmfifoNetListener_AcceptAndClose(t *testing.T) {
	t.Log("Testing TmfifoNetListener Accept and Close cycle")
	listener, err := NewTmfifoNetListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewTmfifoNetListener failed: %v", err)
	}

	// Get the actual address the listener is bound to
	tcpListener := listener.listener.(*net.TCPListener)
	addr := tcpListener.Addr().String()

	// Connect from client in goroutine
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(100 * time.Millisecond)
	}()

	// Accept should succeed
	transport, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}

	if transport.Type() != TransportTmfifoNet {
		t.Errorf("accepted transport Type() = %s, want %s", transport.Type(), TransportTmfifoNet)
	}

	// Close the transport
	transport.Close()

	// Wait for client
	<-clientDone

	// Close the listener
	err = listener.Close()
	if err != nil {
		t.Errorf("listener Close failed: %v", err)
	}
}

func TestTmfifoNetListener_DoubleClose(t *testing.T) {
	t.Log("Testing TmfifoNetListener Close is safe to call twice")
	listener, _ := NewTmfifoNetListener("127.0.0.1:0")
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
	t.Log("Testing TmfifoNetListener Accept returns error after Close")
	listener, _ := NewTmfifoNetListener("127.0.0.1:0")
	listener.Close()

	// Accept after close should fail
	_, err := listener.Accept()
	if err == nil {
		t.Error("expected error on Accept after Close")
	}
}

func TestTmfifoNetListener_UnixSocket(t *testing.T) {
	t.Log("Testing TmfifoNetListener with Unix socket")
	socketPath := testSocketPath("list")
	t.Cleanup(func() { os.Remove(socketPath) })

	listener, err := NewTmfifoNetListenerWithSocket("", socketPath)
	if err != nil {
		t.Fatalf("NewTmfifoNetListenerWithSocket failed: %v", err)
	}

	if !listener.useUnixSocket {
		t.Error("expected useUnixSocket = true")
	}

	// Connect client
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(100 * time.Millisecond)
	}()

	// Accept
	transport, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}

	transport.Close()
	<-clientDone
	listener.Close()

	// Socket file should be cleaned up
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Error("expected socket file to be removed after Close")
	}
}

func TestNewTmfifoNetTransportFromConn(t *testing.T) {
	t.Log("Testing newTmfifoNetTransportFromConn creates transport from existing connection")
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	transport := newTmfifoNetTransportFromConn(client)

	if !transport.connected {
		t.Error("expected connected = true when created from conn")
	}
	if transport.conn != client {
		t.Error("expected conn to be set")
	}
	if transport.reader == nil {
		t.Error("expected reader to be set")
	}

	transport.Close()
}

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestIsUnixSocket(t *testing.T) {
	t.Log("Testing isUnixSocket correctly identifies socket files vs regular files")
	socketPath := testSocketPath("issock")
	t.Cleanup(func() { os.Remove(socketPath) })

	// Create a Unix socket
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create Unix socket: %v", err)
	}
	defer listener.Close()

	if !isUnixSocket(socketPath) {
		t.Error("expected isUnixSocket to return true for Unix socket")
	}

	// Create a regular file
	regularFile := "/tmp/tmfifo_test_regular.txt"
	f, _ := os.Create(regularFile)
	f.Close()
	t.Cleanup(func() { os.Remove(regularFile) })

	if isUnixSocket(regularFile) {
		t.Error("expected isUnixSocket to return false for regular file")
	}

	// Non-existent path
	if isUnixSocket("/nonexistent/path") {
		t.Error("expected isUnixSocket to return false for non-existent path")
	}
}

func TestHasTmfifoInterface(t *testing.T) {
	t.Log("Testing hasTmfifoInterface doesn't panic (tmfifo_net0 usually absent)")
	result := hasTmfifoInterface()
	t.Logf("hasTmfifoInterface() = %v", result)
}

func TestHasTmfifoInterface_Exported(t *testing.T) {
	t.Log("Testing exported HasTmfifoInterface function")
	result := HasTmfifoInterface()
	t.Logf("HasTmfifoInterface() = %v", result)
}

// ============================================================================
// Integration Tests
// ============================================================================

func TestTmfifoRoundTrip(t *testing.T) {
	t.Log("Testing full round-trip message exchange over tmfifo transport")
	serverListener, err := NewTmfifoNetListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create server listener: %v", err)
	}
	defer serverListener.Close()

	// Get actual bound address
	tcpListener := serverListener.listener.(*net.TCPListener)
	addr := tcpListener.Addr().String()

	// Create client transport
	clientTransport, err := NewTmfifoNetTransport(addr)
	if err != nil {
		t.Fatalf("failed to create client transport: %v", err)
	}
	defer clientTransport.Close()

	// Server accepts in background
	serverCh := make(chan Transport)
	go func() {
		transport, _ := serverListener.Accept()
		serverCh <- transport
	}()

	// Client connects
	ctx := context.Background()
	if err := clientTransport.Connect(ctx); err != nil {
		t.Fatalf("client Connect failed: %v", err)
	}

	serverTransport := <-serverCh
	defer serverTransport.Close()

	// Send message from client to server
	msg := &Message{
		Version: ProtocolVersion,
		Type:    MessageEnrollRequest,
		ID:      "round-trip-test",
		TS:      time.Now().UnixMilli(),
		Payload: json.RawMessage(`{"hostname":"test-host"}`),
	}

	if err := clientTransport.Send(msg); err != nil {
		t.Fatalf("client Send failed: %v", err)
	}

	// Server receives
	received, err := serverTransport.Recv()
	if err != nil {
		t.Fatalf("server Recv failed: %v", err)
	}

	if received.Type != msg.Type {
		t.Errorf("received Type = %s, want %s", received.Type, msg.Type)
	}
	if received.ID != msg.ID {
		t.Errorf("received ID = %s, want %s", received.ID, msg.ID)
	}

	// Send response from server to client
	response := &Message{
		Version: ProtocolVersion,
		Type:    MessageEnrollResponse,
		ID:      "round-trip-test",
		TS:      time.Now().UnixMilli(),
		Payload: json.RawMessage(`{"success":true,"host_id":"host_123"}`),
	}

	if err := serverTransport.Send(response); err != nil {
		t.Fatalf("server Send failed: %v", err)
	}

	// Client receives response
	receivedResp, err := clientTransport.Recv()
	if err != nil {
		t.Fatalf("client Recv failed: %v", err)
	}

	if receivedResp.Type != MessageEnrollResponse {
		t.Errorf("response Type = %s, want %s", receivedResp.Type, MessageEnrollResponse)
	}
}
