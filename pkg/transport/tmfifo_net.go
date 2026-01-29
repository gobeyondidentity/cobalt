// Package transport provides communication abstractions for Host-DPU communication.
//
// # Tmfifo Transport Architecture
//
// The tmfifo_net0 interface is a NETWORK INTERFACE, not a character device.
// Previous implementations incorrectly attempted to open /dev/tmfifo_net0 as a file,
// which only worked in tests because socat creates a Unix socket at that path.
//
// On real BlueField hardware, tmfifo_net0 appears as a standard network interface
// (like eth0) with IP addresses assigned to both the DPU and host sides:
//   - DPU side: typically 192.168.100.2
//   - Host side: typically 192.168.100.1
//
// This implementation uses TCP sockets over the tmfifo_net0 interface:
//   - DPU (aegis) listens on 0.0.0.0:9444
//   - Host (sentry) connects to the DPU address (default 192.168.100.2:9444)
//
// # Transport Selection Priority
//
//  1. DOCA Comch (future, already stubbed) - highest performance
//  2. Tmfifo TCP (this implementation) - when tmfifo_net0 interface exists
//  3. Emulated socket (testing) - when Unix socket file exists at configured path
//  4. Network fallback (existing) - for non-BlueField deployments
//
// See ADR-005 and ADR-007 for architectural decisions.
package transport

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

const (
	// maxMessageSize limits the size of incoming messages over tmfifo.
	maxMessageSize = 64 * 1024 // 64KB

	// tcpDialTimeout is the timeout for TCP connection attempts.
	tcpDialTimeout = 10 * time.Second
)

var (
	// ErrTmfifoDeviceNotFound indicates the tmfifo interface/socket does not exist.
	ErrTmfifoDeviceNotFound = errors.New("tmfifo interface or socket not found")

	// ErrTmfifoAlreadyConnected indicates the transport already has an active connection.
	ErrTmfifoAlreadyConnected = errors.New("tmfifo transport already has active connection")
)

// TmfifoNetTransport implements Transport using TCP over the tmfifo_net0 interface.
// This transport uses TCP sockets for bidirectional communication between DPU and host.
// For test compatibility, it also supports Unix domain sockets when a socket file exists.
type TmfifoNetTransport struct {
	conn       net.Conn
	dpuAddr    string // TCP address for tmfifo (e.g., "192.168.100.2:9444")
	socketPath string // Unix socket path for testing (e.g., "/tmp/tmfifo.sock")
	reader     *bufio.Reader

	useUnixSocket bool // true if using Unix socket (test mode)
	connected     bool
	closed        bool
	mu            sync.Mutex
}

// newTmfifoNetTransportFromConn creates a transport wrapping an already-established connection.
// Used internally by TmfifoNetListener.Accept().
func newTmfifoNetTransportFromConn(conn net.Conn) *TmfifoNetTransport {
	return &TmfifoNetTransport{
		conn:      conn,
		reader:    bufio.NewReaderSize(conn, maxMessageSize),
		connected: true,
	}
}

// NewTmfifoNetTransport creates a client-side transport for tmfifo communication.
// It detects whether to use TCP (real hardware) or Unix socket (test emulation).
//
// Parameters:
//   - dpuAddr: TCP address of the DPU (e.g., "192.168.100.2:9444"). If empty, uses default.
//   - socketPath: Path for Unix socket emulation (test mode). If empty, uses TCP only.
//
// Call Connect() to establish the connection before use.
func NewTmfifoNetTransport(dpuAddr string) (Transport, error) {
	if dpuAddr == "" {
		dpuAddr = TmfifoDefaultDPUAddr
	}

	return &TmfifoNetTransport{
		dpuAddr: dpuAddr,
	}, nil
}

// NewTmfifoNetTransportWithSocket creates a transport that prefers Unix socket if available.
// This is used for test compatibility with socat emulation.
func NewTmfifoNetTransportWithSocket(dpuAddr, socketPath string) (Transport, error) {
	if dpuAddr == "" {
		dpuAddr = TmfifoDefaultDPUAddr
	}

	t := &TmfifoNetTransport{
		dpuAddr:    dpuAddr,
		socketPath: socketPath,
	}

	// Check if Unix socket exists (test mode)
	if socketPath != "" && isUnixSocket(socketPath) {
		t.useUnixSocket = true
		log.Printf("tmfifo: detected Unix socket at %s (test mode)", socketPath)
	}

	return t, nil
}

// Connect establishes the tmfifo connection.
// For server-side transports returned by Accept(), this is a no-op.
// For client-side transports, this dials either TCP or Unix socket.
func (t *TmfifoNetTransport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return errors.New("transport closed")
	}
	if t.connected {
		return nil // Already connected
	}

	var conn net.Conn
	var err error
	var dialer net.Dialer
	dialer.Timeout = tcpDialTimeout

	if t.useUnixSocket && t.socketPath != "" {
		// Unix socket mode (testing with socat)
		conn, err = dialer.DialContext(ctx, "unix", t.socketPath)
		if err != nil {
			return fmt.Errorf("connect to tmfifo Unix socket %s: %w", t.socketPath, err)
		}
		log.Printf("tmfifo: connected via Unix socket %s", t.socketPath)
	} else {
		// TCP mode (real hardware)
		conn, err = dialer.DialContext(ctx, "tcp", t.dpuAddr)
		if err != nil {
			return fmt.Errorf("connect to tmfifo TCP %s: %w", t.dpuAddr, err)
		}
		log.Printf("tmfifo: connected via TCP to %s", t.dpuAddr)
	}

	t.conn = conn
	t.reader = bufio.NewReaderSize(conn, maxMessageSize)
	t.connected = true

	return nil
}

// Send transmits a message over the tmfifo connection.
// Messages are JSON-encoded and newline-delimited.
func (t *TmfifoNetTransport) Send(msg *Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return errors.New("transport closed")
	}
	if !t.connected {
		return errors.New("transport not connected")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	// Write message with newline delimiter
	data = append(data, '\n')
	if _, err := t.conn.Write(data); err != nil {
		return fmt.Errorf("write to tmfifo: %w", err)
	}

	log.Printf("tmfifo: sent %s message (nonce=%s)", msg.Type, msg.ID)
	return nil
}

// Recv blocks until a message is received from the tmfifo connection.
// Returns io.EOF if the connection is closed.
func (t *TmfifoNetTransport) Recv() (*Message, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, io.EOF
	}
	if !t.connected {
		t.mu.Unlock()
		return nil, errors.New("transport not connected")
	}
	reader := t.reader
	t.mu.Unlock()

	// Read until newline (message delimiter)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		if err == io.EOF || errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("read from tmfifo: %w", err)
	}

	if len(line) == 0 {
		return nil, errors.New("empty message received")
	}

	var msg Message
	if err := json.Unmarshal(line, &msg); err != nil {
		return nil, fmt.Errorf("parse message: %w", err)
	}

	log.Printf("tmfifo: received %s message (nonce=%s)", msg.Type, msg.ID)
	return &msg, nil
}

// Close terminates the transport and releases the connection.
func (t *TmfifoNetTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	t.closed = true
	t.connected = false

	if t.conn != nil {
		if err := t.conn.Close(); err != nil {
			return fmt.Errorf("close tmfifo connection: %w", err)
		}
		t.conn = nil
	}

	log.Printf("tmfifo: transport closed")
	return nil
}

// Reset clears the closed state, allowing the transport to reconnect.
// This is used by sentry for automatic reconnection after aegis restarts.
// The transport must be closed before calling Reset.
func (t *TmfifoNetTransport) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.closed = false
	t.connected = false
	t.conn = nil
	t.reader = nil

	log.Printf("tmfifo: transport reset for reconnection")
}

// Type returns TransportTmfifoNet.
func (t *TmfifoNetTransport) Type() TransportType {
	return TransportTmfifoNet
}

// TmfifoNetListener implements TransportListener for the tmfifo TCP transport.
// It listens on a TCP port for connections from host agents.
// For test compatibility, it also supports Unix domain sockets.
type TmfifoNetListener struct {
	listener   net.Listener
	listenAddr string // TCP listen address (e.g., ":9444" or "0.0.0.0:9444")
	socketPath string // Unix socket path for testing

	useUnixSocket bool
	closed        bool
	mu            sync.Mutex
}

// NewTmfifoNetListener creates a TCP listener for tmfifo connections.
// The listener binds to the specified address and waits for host agent connections.
func NewTmfifoNetListener(listenAddr string) (*TmfifoNetListener, error) {
	if listenAddr == "" {
		listenAddr = fmt.Sprintf(":%d", TmfifoListenPort)
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", listenAddr, err)
	}

	log.Printf("tmfifo: listening on TCP %s", listenAddr)

	return &TmfifoNetListener{
		listener:   listener,
		listenAddr: listenAddr,
	}, nil
}

// NewTmfifoNetListenerWithSocket creates a listener that uses Unix socket if path provided.
// This is used for test compatibility with socat emulation.
func NewTmfifoNetListenerWithSocket(listenAddr, socketPath string) (*TmfifoNetListener, error) {
	if socketPath != "" {
		// Unix socket mode (testing)
		// Remove existing socket file if present
		os.Remove(socketPath)

		listener, err := net.Listen("unix", socketPath)
		if err != nil {
			return nil, fmt.Errorf("listen on Unix socket %s: %w", socketPath, err)
		}

		log.Printf("tmfifo: listening on Unix socket %s (test mode)", socketPath)

		return &TmfifoNetListener{
			listener:      listener,
			socketPath:    socketPath,
			useUnixSocket: true,
		}, nil
	}

	// TCP mode
	return NewTmfifoNetListener(listenAddr)
}

// Accept blocks until a new connection is received.
// Returns a Transport for communicating with the connected host agent.
func (l *TmfifoNetListener) Accept() (Transport, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, errors.New("listener closed")
	}
	listener := l.listener
	l.mu.Unlock()

	conn, err := listener.Accept()
	if err != nil {
		l.mu.Lock()
		closed := l.closed
		l.mu.Unlock()
		if closed {
			return nil, errors.New("listener closed")
		}
		return nil, fmt.Errorf("accept tmfifo connection: %w", err)
	}

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("tmfifo: accepted connection from %s", remoteAddr)

	return newTmfifoNetTransportFromConn(conn), nil
}

// Close stops the listener and releases resources.
func (l *TmfifoNetListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}

	l.closed = true

	if l.listener != nil {
		if err := l.listener.Close(); err != nil {
			return fmt.Errorf("close tmfifo listener: %w", err)
		}
	}

	// Clean up Unix socket file if used
	if l.useUnixSocket && l.socketPath != "" {
		os.Remove(l.socketPath)
	}

	log.Printf("tmfifo: listener closed")
	return nil
}

// Type returns TransportTmfifoNet.
func (l *TmfifoNetListener) Type() TransportType {
	return TransportTmfifoNet
}

// isUnixSocket checks if the path exists and is a Unix domain socket.
func isUnixSocket(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSocket != 0
}

// hasTmfifoInterface checks if the tmfifo_net0 network interface exists.
func hasTmfifoInterface() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.Name == TmfifoInterfaceName {
			return true
		}
	}
	return false
}

// HasTmfifoInterface returns true if the tmfifo_net0 network interface exists.
// This is the primary indicator that we're running on BlueField hardware.
func HasTmfifoInterface() bool {
	return hasTmfifoInterface()
}
