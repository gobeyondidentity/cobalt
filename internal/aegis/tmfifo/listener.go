// Package tmfifo provides communication with the Host Agent over the BlueField tmfifo interface.
//
// # Architecture
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
//   - Host (sentry) connects to the DPU address
//
// For test compatibility, the Listener also supports Unix domain sockets when
// a socket path is provided, allowing socat-based emulation to continue working.
//
// See ADR-005 and ADR-007 for architectural decisions.
package tmfifo

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
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
	// DefaultListenAddr is the default TCP address for the tmfifo listener.
	DefaultListenAddr = ":9444"

	// TmfifoInterfaceName is the network interface name for tmfifo communication.
	TmfifoInterfaceName = "tmfifo_net0"

	// nonceExpiry is how long nonces are tracked for replay protection.
	nonceExpiry = 5 * time.Minute

	// maxMessageSize limits the size of incoming messages.
	maxMessageSize = 64 * 1024 // 64KB
)

// Deprecated: DefaultDevicePath is deprecated. tmfifo_net0 is a network interface, not a device.
// Use DefaultListenAddr for TCP listening or provide a socketPath for Unix socket testing.
const DefaultDevicePath = "/dev/tmfifo_net0"

// Deprecated: devicePaths is deprecated. tmfifo_net0 is a network interface, not a device file.
var devicePaths = []string{}

var (
	// ErrDeviceNotFound indicates the tmfifo interface does not exist.
	ErrDeviceNotFound = errors.New("tmfifo interface not found")

	// ErrReplayDetected indicates a duplicate nonce was received.
	ErrReplayDetected = errors.New("replay attack detected: duplicate nonce")

	// ErrMessageTooLarge indicates a message exceeded the size limit.
	ErrMessageTooLarge = errors.New("message exceeds maximum size")
)

// MessageHandler processes incoming tmfifo messages.
// Implementations should handle ENROLL_REQUEST and POSTURE_REPORT message types.
type MessageHandler interface {
	// HandleEnroll processes an enrollment request from the Host Agent.
	HandleEnroll(ctx context.Context, hostname string, posture json.RawMessage) (*EnrollResponsePayload, error)

	// HandlePosture processes a posture update from the Host Agent.
	HandlePosture(ctx context.Context, hostname string, posture json.RawMessage) (*PostureAckPayload, error)
}

// Listener handles bidirectional communication with the Host Agent over tmfifo.
// It uses TCP sockets on real hardware or Unix domain sockets for testing.
type Listener struct {
	listenAddr string // TCP listen address (e.g., ":9444")
	socketPath string // Unix socket path for testing
	handler    MessageHandler

	listener   net.Listener
	activeConn net.Conn
	connMu     sync.Mutex

	seenNonces map[string]time.Time
	nonceMu    sync.RWMutex

	useUnixSocket bool
	stopCh        chan struct{}
	wg            sync.WaitGroup
	started       bool
	startMu       sync.Mutex
}

// NewListener creates a tmfifo listener.
// The handler is called for incoming ENROLL_REQUEST and POSTURE_REPORT messages.
//
// Parameters:
//   - listenAddr: TCP address to listen on (e.g., ":9444"). If empty, uses DefaultListenAddr.
//   - handler: MessageHandler for processing incoming messages.
//
// For backward compatibility, if listenAddr looks like a device path (starts with /dev/),
// it's treated as a Unix socket path for testing.
func NewListener(listenAddr string, handler MessageHandler) *Listener {
	l := &Listener{
		handler:    handler,
		seenNonces: make(map[string]time.Time),
		stopCh:     make(chan struct{}),
	}

	// Backward compatibility: if path starts with /dev/, treat as Unix socket for testing
	if len(listenAddr) > 0 && listenAddr[0] == '/' {
		l.socketPath = listenAddr
		l.useUnixSocket = true
		log.Printf("tmfifo: configured for Unix socket at %s (test mode)", listenAddr)
	} else if listenAddr == "" {
		l.listenAddr = DefaultListenAddr
	} else {
		l.listenAddr = listenAddr
	}

	return l
}

// NewListenerWithSocket creates a tmfifo listener that uses Unix socket for testing.
func NewListenerWithSocket(listenAddr, socketPath string, handler MessageHandler) *Listener {
	l := &Listener{
		listenAddr: listenAddr,
		socketPath: socketPath,
		handler:    handler,
		seenNonces: make(map[string]time.Time),
		stopCh:     make(chan struct{}),
	}

	if socketPath != "" {
		l.useUnixSocket = true
		log.Printf("tmfifo: configured for Unix socket at %s (test mode)", socketPath)
	} else if listenAddr == "" {
		l.listenAddr = DefaultListenAddr
	}

	return l
}

// DevicePath returns the configured Unix socket path (for backward compatibility).
// Deprecated: Use ListenAddr() instead for TCP or SocketPath() for Unix sockets.
func (l *Listener) DevicePath() string {
	if l.useUnixSocket {
		return l.socketPath
	}
	return l.listenAddr
}

// ListenAddr returns the TCP listen address.
func (l *Listener) ListenAddr() string {
	return l.listenAddr
}

// SocketPath returns the Unix socket path (empty if using TCP).
func (l *Listener) SocketPath() string {
	return l.socketPath
}

// Start begins listening for connections and processing messages.
// Returns ErrDeviceNotFound if the tmfifo interface doesn't exist (unless using Unix socket).
func (l *Listener) Start(ctx context.Context) error {
	l.startMu.Lock()
	defer l.startMu.Unlock()

	if l.started {
		return errors.New("listener already started")
	}

	var listener net.Listener
	var err error

	if l.useUnixSocket {
		// Unix socket mode (testing)
		// Check if path is actually a device file (backward compat with tests using fake files)
		info, statErr := os.Stat(l.socketPath)
		if statErr != nil && os.IsNotExist(statErr) {
			return ErrDeviceNotFound
		}
		if statErr == nil && info.Mode().IsRegular() {
			// It's a regular file (test compatibility), open as file-based transport
			// For full backward compat, we need a different approach
			return l.startWithFile(ctx)
		}

		// Remove existing socket file if present
		os.Remove(l.socketPath)

		listener, err = net.Listen("unix", l.socketPath)
		if err != nil {
			return fmt.Errorf("listen on Unix socket %s: %w", l.socketPath, err)
		}
		log.Printf("tmfifo: listening on Unix socket %s (test mode)", l.socketPath)
	} else {
		// TCP mode
		listener, err = net.Listen("tcp", l.listenAddr)
		if err != nil {
			return fmt.Errorf("listen on %s: %w", l.listenAddr, err)
		}
		log.Printf("tmfifo: listening on TCP %s", l.listenAddr)
	}

	l.listener = listener
	l.started = true

	// Start the connection accept loop
	l.wg.Add(1)
	go l.acceptLoop(ctx)

	// Start nonce cleanup goroutine
	l.wg.Add(1)
	go l.nonceCleanupLoop(ctx)

	return nil
}

// startWithFile handles backward compatibility with tests that use regular files.
// This opens the file for read/write and processes messages.
func (l *Listener) startWithFile(ctx context.Context) error {
	device, err := os.OpenFile(l.socketPath, os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open tmfifo file: %w", err)
	}

	// Wrap file in a fake net.Conn for compatibility
	l.connMu.Lock()
	l.activeConn = &fileConn{file: device}
	l.connMu.Unlock()

	l.started = true

	// Start reading from file
	l.wg.Add(1)
	go l.readLoop(ctx)

	// Start nonce cleanup goroutine
	l.wg.Add(1)
	go l.nonceCleanupLoop(ctx)

	log.Printf("tmfifo: listening on file %s (test mode)", l.socketPath)
	return nil
}

// fileConn wraps an os.File to implement net.Conn for backward compatibility.
type fileConn struct {
	file *os.File
}

func (f *fileConn) Read(b []byte) (n int, err error)   { return f.file.Read(b) }
func (f *fileConn) Write(b []byte) (n int, err error)  { return f.file.Write(b) }
func (f *fileConn) Close() error                       { return f.file.Close() }
func (f *fileConn) LocalAddr() net.Addr                { return &net.UnixAddr{Name: f.file.Name()} }
func (f *fileConn) RemoteAddr() net.Addr               { return &net.UnixAddr{Name: "remote"} }
func (f *fileConn) SetDeadline(t time.Time) error      { return f.file.SetDeadline(t) }
func (f *fileConn) SetReadDeadline(t time.Time) error  { return f.file.SetReadDeadline(t) }
func (f *fileConn) SetWriteDeadline(t time.Time) error { return f.file.SetWriteDeadline(t) }

// acceptLoop accepts incoming connections and starts read loops for each.
func (l *Listener) acceptLoop(ctx context.Context) {
	defer l.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stopCh:
			return
		default:
		}

		conn, err := l.listener.Accept()
		if err != nil {
			select {
			case <-l.stopCh:
				return
			default:
				log.Printf("tmfifo: accept error: %v", err)
				continue
			}
		}

		remoteAddr := conn.RemoteAddr().String()
		log.Printf("tmfifo: accepted connection from %s", remoteAddr)

		// Store the active connection
		l.connMu.Lock()
		if l.activeConn != nil {
			// Close previous connection
			l.activeConn.Close()
		}
		l.activeConn = conn
		l.connMu.Unlock()

		// Start read loop for this connection
		l.wg.Add(1)
		go l.readLoopForConn(ctx, conn)
	}
}

// readLoopForConn reads messages from a specific connection.
func (l *Listener) readLoopForConn(ctx context.Context, conn net.Conn) {
	defer l.wg.Done()

	reader := bufio.NewReaderSize(conn, maxMessageSize)

	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stopCh:
			return
		default:
		}

		// Read until newline (message delimiter)
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF || errors.Is(err, net.ErrClosed) {
				log.Printf("tmfifo: connection closed")
				return
			}
			if errors.Is(err, os.ErrClosed) {
				return
			}
			log.Printf("tmfifo: read error: %v", err)
			continue
		}

		if len(line) == 0 {
			continue
		}

		// Parse and handle the message
		if err := l.handleMessage(ctx, line); err != nil {
			log.Printf("tmfifo: message handling error: %v", err)
		}
	}
}

// Stop gracefully shuts down the listener.
func (l *Listener) Stop() error {
	l.startMu.Lock()
	defer l.startMu.Unlock()

	if !l.started {
		return nil
	}

	close(l.stopCh)

	// Close listener first to unblock Accept
	if l.listener != nil {
		l.listener.Close()
	}

	// Close active connection
	l.connMu.Lock()
	if l.activeConn != nil {
		l.activeConn.Close()
	}
	l.connMu.Unlock()

	l.wg.Wait()

	// Clean up Unix socket file if used
	if l.useUnixSocket && l.socketPath != "" {
		os.Remove(l.socketPath)
	}

	l.started = false
	log.Printf("tmfifo: listener stopped")
	return nil
}

// SendCredentialPush sends a credential to the Host Agent.
// Returns an error if no connection is active.
func (l *Listener) SendCredentialPush(credType, credName string, data []byte) error {
	payload := CredentialPushPayload{
		CredentialType: credType,
		CredentialName: credName,
		Data:           data,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal credential payload: %w", err)
	}

	msg := Message{
		Type:    TypeCredentialPush,
		Payload: payloadBytes,
		ID:      generateNonce(),
	}

	return l.sendMessage(&msg)
}

// sendMessage writes a message to the active connection.
func (l *Listener) sendMessage(msg *Message) error {
	l.connMu.Lock()
	conn := l.activeConn
	l.connMu.Unlock()

	if conn == nil {
		return errors.New("tmfifo: no active connection")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	// Write message with newline delimiter
	data = append(data, '\n')
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("write to tmfifo: %w", err)
	}

	log.Printf("tmfifo: sent %s message (nonce=%s)", msg.Type, msg.ID)
	return nil
}

// readLoop continuously reads and processes messages from the active connection.
// Used for file-based backward compatibility.
func (l *Listener) readLoop(ctx context.Context) {
	defer l.wg.Done()

	l.connMu.Lock()
	conn := l.activeConn
	l.connMu.Unlock()

	if conn == nil {
		return
	}

	reader := bufio.NewReaderSize(conn, maxMessageSize)

	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stopCh:
			return
		default:
		}

		// Read until newline (message delimiter)
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				// EOF is normal when device is closed
				continue
			}
			if errors.Is(err, os.ErrClosed) {
				return
			}
			log.Printf("tmfifo: read error: %v", err)
			continue
		}

		if len(line) == 0 {
			continue
		}

		// Parse and handle the message
		if err := l.handleMessage(ctx, line); err != nil {
			log.Printf("tmfifo: message handling error: %v", err)
		}
	}
}

// handleMessage parses and dispatches an incoming message.
func (l *Listener) handleMessage(ctx context.Context, data []byte) error {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return fmt.Errorf("parse message: %w", err)
	}

	// Check for replay attacks
	if msg.ID != "" {
		if !l.recordNonce(msg.ID) {
			return ErrReplayDetected
		}
	}

	log.Printf("tmfifo: received %s message (nonce=%s)", msg.Type, msg.ID)

	switch msg.Type {
	case TypeEnrollRequest:
		return l.handleEnrollRequest(ctx, &msg)
	case TypePostureReport:
		return l.handlePostureReport(ctx, &msg)
	case TypeCredentialAck:
		return l.handleCredentialAck(&msg)
	default:
		log.Printf("tmfifo: unknown message type: %s", msg.Type)
		return nil
	}
}

// handleEnrollRequest processes an ENROLL_REQUEST from the Host Agent.
func (l *Listener) handleEnrollRequest(ctx context.Context, msg *Message) error {
	var payload EnrollRequestPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return fmt.Errorf("parse enroll request: %w", err)
	}

	if l.handler == nil {
		return errors.New("no handler configured")
	}

	resp, err := l.handler.HandleEnroll(ctx, payload.Hostname, payload.Posture)
	if err != nil {
		resp = &EnrollResponsePayload{
			Success: false,
			Error:   err.Error(),
		}
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal enroll response: %w", err)
	}

	respMsg := Message{
		Type:    TypeEnrollResponse,
		Payload: respBytes,
		ID:      generateNonce(),
	}

	return l.sendMessage(&respMsg)
}

// handlePostureReport processes a POSTURE_REPORT from the Host Agent.
func (l *Listener) handlePostureReport(ctx context.Context, msg *Message) error {
	var payload PostureReportPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return fmt.Errorf("parse posture report: %w", err)
	}

	if l.handler == nil {
		return errors.New("no handler configured")
	}

	resp, err := l.handler.HandlePosture(ctx, payload.Hostname, payload.Posture)
	if err != nil {
		resp = &PostureAckPayload{
			Accepted: false,
			Error:    err.Error(),
		}
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal posture ack: %w", err)
	}

	respMsg := Message{
		Type:    TypePostureAck,
		Payload: respBytes,
		ID:      generateNonce(),
	}

	return l.sendMessage(&respMsg)
}

// handleCredentialAck processes a CREDENTIAL_ACK from the Host Agent.
func (l *Listener) handleCredentialAck(msg *Message) error {
	var payload CredentialAckPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return fmt.Errorf("parse credential ack: %w", err)
	}

	if payload.Success {
		log.Printf("tmfifo: credential installed at %s", payload.InstalledPath)
	} else {
		log.Printf("tmfifo: credential installation failed: %s", payload.Error)
	}

	return nil
}

// recordNonce tracks a nonce for replay protection.
// Returns true if the nonce is new, false if it was already seen.
func (l *Listener) recordNonce(nonce string) bool {
	l.nonceMu.Lock()
	defer l.nonceMu.Unlock()

	if _, seen := l.seenNonces[nonce]; seen {
		return false
	}

	l.seenNonces[nonce] = time.Now()
	return true
}

// nonceCleanupLoop periodically removes expired nonces.
func (l *Listener) nonceCleanupLoop(ctx context.Context) {
	defer l.wg.Done()

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stopCh:
			return
		case <-ticker.C:
			l.cleanupNonces()
		}
	}
}

// cleanupNonces removes nonces older than nonceExpiry.
func (l *Listener) cleanupNonces() {
	l.nonceMu.Lock()
	defer l.nonceMu.Unlock()

	cutoff := time.Now().Add(-nonceExpiry)
	for nonce, seen := range l.seenNonces {
		if seen.Before(cutoff) {
			delete(l.seenNonces, nonce)
		}
	}
}

// generateNonce creates a random 32-byte hex-encoded nonce.
func generateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
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

// IsAvailable checks if the tmfifo_net0 network interface exists.
func IsAvailable() bool {
	return hasTmfifoInterface()
}

// DetectDevice checks if the tmfifo_net0 network interface exists.
// Returns true and the interface name if found, false and empty string otherwise.
func DetectDevice() (bool, string) {
	if hasTmfifoInterface() {
		return true, TmfifoInterfaceName
	}
	return false, ""
}

// IsAvailableAt checks if a Unix socket exists at the specified path.
// This is used for test compatibility with socat emulation.
func IsAvailableAt(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	// Accept socket, regular file, or device (for backward compat with tests)
	return info.Mode()&os.ModeSocket != 0 || info.Mode().IsRegular() || info.Mode()&os.ModeDevice != 0
}

// CredentialPushResult contains the result of pushing a credential to the Host Agent.
type CredentialPushResult struct {
	Success       bool
	Message       string
	InstalledPath string
	SshdReloaded  bool
}

// PushCredential sends a credential to the Host Agent and returns the result.
// This is a higher-level wrapper around SendCredentialPush that provides
// a structured result for the DPU Agent's gRPC handler.
//
// Note: tmfifo is asynchronous; this method sends the push but cannot wait
// for the ack. The caller should use SendCredentialPush directly if they need
// to handle the async ack via handleCredentialAck.
func (l *Listener) PushCredential(credType, credName string, data []byte) (*CredentialPushResult, error) {
	if err := l.SendCredentialPush(credType, credName, data); err != nil {
		return nil, fmt.Errorf("tmfifo send failed: %w", err)
	}

	// tmfifo is asynchronous; we sent the push but cannot wait for ack here
	// The ack will be processed by handleCredentialAck when it arrives
	return &CredentialPushResult{
		Success: true,
		Message: fmt.Sprintf("Credential '%s' sent to host via tmfifo. Awaiting installation ack.", credName),
	}, nil
}
