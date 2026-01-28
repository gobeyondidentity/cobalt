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
	"os"
	"sync"
	"time"
)

const (
	// DefaultDevicePath is the standard tmfifo device path on BlueField.
	DefaultDevicePath = "/dev/tmfifo_net0"

	// nonceExpiry is how long nonces are tracked for replay protection.
	nonceExpiry = 5 * time.Minute

	// maxMessageSize limits the size of incoming messages.
	maxMessageSize = 64 * 1024 // 64KB
)

var (
	// ErrDeviceNotFound indicates the tmfifo device does not exist.
	ErrDeviceNotFound = errors.New("tmfifo device not found")

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
type Listener struct {
	devicePath string
	handler    MessageHandler

	device     *os.File
	deviceMu   sync.Mutex
	seenNonces map[string]time.Time
	nonceMu    sync.RWMutex

	stopCh   chan struct{}
	wg       sync.WaitGroup
	started  bool
	startMu  sync.Mutex
}

// NewListener creates a tmfifo listener.
// The handler is called for incoming ENROLL_REQUEST and POSTURE_REPORT messages.
func NewListener(devicePath string, handler MessageHandler) *Listener {
	if devicePath == "" {
		devicePath = DefaultDevicePath
	}
	return &Listener{
		devicePath: devicePath,
		handler:    handler,
		seenNonces: make(map[string]time.Time),
		stopCh:     make(chan struct{}),
	}
}

// DevicePath returns the configured tmfifo device path.
func (l *Listener) DevicePath() string {
	return l.devicePath
}

// Start opens the tmfifo device and begins processing messages.
// Returns ErrDeviceNotFound if the device does not exist.
func (l *Listener) Start(ctx context.Context) error {
	l.startMu.Lock()
	defer l.startMu.Unlock()

	if l.started {
		return errors.New("listener already started")
	}

	// Check if device exists
	if _, err := os.Stat(l.devicePath); os.IsNotExist(err) {
		return ErrDeviceNotFound
	}

	// Open device for read/write
	device, err := os.OpenFile(l.devicePath, os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open tmfifo device: %w", err)
	}
	l.device = device
	l.started = true

	// Start the message processing goroutine
	l.wg.Add(1)
	go l.readLoop(ctx)

	// Start nonce cleanup goroutine
	l.wg.Add(1)
	go l.nonceCleanupLoop(ctx)

	log.Printf("tmfifo: listening on %s", l.devicePath)
	return nil
}

// Stop gracefully shuts down the listener.
func (l *Listener) Stop() error {
	l.startMu.Lock()
	defer l.startMu.Unlock()

	if !l.started {
		return nil
	}

	close(l.stopCh)
	l.wg.Wait()

	if l.device != nil {
		if err := l.device.Close(); err != nil {
			return fmt.Errorf("close tmfifo device: %w", err)
		}
	}

	l.started = false
	log.Printf("tmfifo: listener stopped")
	return nil
}

// SendCredentialPush sends a credential to the Host Agent.
// Returns the CredentialAckPayload from the host, or an error.
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
		ID:   generateNonce(),
	}

	return l.sendMessage(&msg)
}

// sendMessage writes a message to the tmfifo device.
func (l *Listener) sendMessage(msg *Message) error {
	l.deviceMu.Lock()
	defer l.deviceMu.Unlock()

	if l.device == nil {
		return errors.New("tmfifo device not open")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	// Write message with newline delimiter
	data = append(data, '\n')
	if _, err := l.device.Write(data); err != nil {
		return fmt.Errorf("write to tmfifo: %w", err)
	}

	log.Printf("tmfifo: sent %s message (nonce=%s)", msg.Type, msg.ID)
	return nil
}

// readLoop continuously reads and processes messages from the tmfifo device.
func (l *Listener) readLoop(ctx context.Context) {
	defer l.wg.Done()

	reader := bufio.NewReaderSize(l.device, maxMessageSize)

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
		ID:   generateNonce(),
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
		ID:   generateNonce(),
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

// IsAvailable checks if the tmfifo device exists at the default path.
func IsAvailable() bool {
	_, err := os.Stat(DefaultDevicePath)
	return err == nil
}

// IsAvailableAt checks if the tmfifo device exists at the specified path.
func IsAvailableAt(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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
