// Package sentry implements the Host Agent functionality.
package sentry

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/nmelo/secure-infra/internal/aegis/tmfifo"
)

const (
	// DefaultTmfifoDPUAddr is the default DPU address for tmfifo TCP connections.
	// This is the standard IP assigned to the DPU side of the tmfifo_net0 interface.
	DefaultTmfifoDPUAddr = "192.168.100.2:9444"

	// TmfifoInterfaceName is the network interface name for tmfifo communication.
	TmfifoInterfaceName = "tmfifo_net0"

	// tmfifoDialTimeout is the timeout for TCP connection attempts.
	tmfifoDialTimeout = 10 * time.Second

	// tmfifoReadTimeout is the timeout for reading from tmfifo.
	tmfifoReadTimeout = 30 * time.Second

	// maxMessageSize limits the size of tmfifo messages.
	maxMessageSize = 64 * 1024 // 64KB
)

// Deprecated: DefaultTmfifoPath is deprecated. Use DefaultTmfifoDPUAddr instead.
// tmfifo_net0 is a network interface, not a device file.
const DefaultTmfifoPath = "/dev/tmfifo_net0"

// TmfifoClient handles communication with the DPU Agent over tmfifo.
// It uses TCP sockets over the tmfifo_net0 network interface for real hardware,
// or Unix domain sockets for test emulation.
type TmfifoClient struct {
	dpuAddr    string   // TCP address of DPU (e.g., "192.168.100.2:9444")
	socketPath string   // Unix socket path for testing
	conn       net.Conn // Active connection
	connMu     sync.Mutex

	useUnixSocket bool // true if using Unix socket (test mode)

	credInstaller *CredentialInstaller
	hostname      string

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewTmfifoClient creates a new tmfifo client using TCP over the tmfifo_net0 interface.
func NewTmfifoClient(dpuAddr, hostname string) *TmfifoClient {
	if dpuAddr == "" {
		dpuAddr = DefaultTmfifoDPUAddr
	}
	return &TmfifoClient{
		dpuAddr:       dpuAddr,
		hostname:      hostname,
		credInstaller: NewCredentialInstaller(),
		stopCh:        make(chan struct{}),
	}
}

// NewTmfifoClientWithSocket creates a tmfifo client that uses Unix socket for testing.
func NewTmfifoClientWithSocket(dpuAddr, socketPath, hostname string) *TmfifoClient {
	if dpuAddr == "" {
		dpuAddr = DefaultTmfifoDPUAddr
	}
	client := &TmfifoClient{
		dpuAddr:       dpuAddr,
		socketPath:    socketPath,
		hostname:      hostname,
		credInstaller: NewCredentialInstaller(),
		stopCh:        make(chan struct{}),
	}

	// Check if Unix socket exists
	if socketPath != "" && isUnixSocket(socketPath) {
		client.useUnixSocket = true
		log.Printf("tmfifo: detected Unix socket at %s (test mode)", socketPath)
	}

	return client
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

// isUnixSocket checks if the path exists and is a Unix domain socket.
func isUnixSocket(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSocket != 0
}

// DetectTmfifo checks if tmfifo transport is available.
// Returns true if either the tmfifo_net0 interface exists or a Unix socket is available.
func DetectTmfifo() (string, bool) {
	if hasTmfifoInterface() {
		return TmfifoInterfaceName, true
	}
	return "", false
}

// DetectTmfifoWithSocket checks for tmfifo availability including Unix socket fallback.
func DetectTmfifoWithSocket(socketPath string) (string, bool) {
	// Check for real interface first
	if hasTmfifoInterface() {
		return TmfifoInterfaceName, true
	}
	// Check for Unix socket (test mode)
	if socketPath != "" && isUnixSocket(socketPath) {
		return socketPath, true
	}
	return "", false
}

// Open establishes the tmfifo connection.
func (c *TmfifoClient) Open() error {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	if c.conn != nil {
		return nil // Already open
	}

	var conn net.Conn
	var err error
	dialer := net.Dialer{Timeout: tmfifoDialTimeout}

	if c.useUnixSocket && c.socketPath != "" {
		// Unix socket mode (testing)
		conn, err = dialer.Dial("unix", c.socketPath)
		if err != nil {
			return fmt.Errorf("connect to tmfifo Unix socket %s: %w", c.socketPath, err)
		}
		log.Printf("tmfifo: connected via Unix socket %s", c.socketPath)
	} else {
		// TCP mode (real hardware)
		conn, err = dialer.Dial("tcp", c.dpuAddr)
		if err != nil {
			return fmt.Errorf("connect to tmfifo TCP %s: %w", c.dpuAddr, err)
		}
		log.Printf("tmfifo: connected via TCP to %s", c.dpuAddr)
	}

	c.conn = conn
	return nil
}

// Close closes the tmfifo connection.
func (c *TmfifoClient) Close() error {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	if c.conn == nil {
		return nil
	}

	// Signal stop to listener
	close(c.stopCh)
	c.wg.Wait()

	err := c.conn.Close()
	c.conn = nil
	return err
}

// Enroll sends an enrollment request to the DPU Agent.
// Returns the assigned host ID on success.
func (c *TmfifoClient) Enroll(posture json.RawMessage) (hostID string, dpuName string, err error) {
	if err := c.Open(); err != nil {
		return "", "", err
	}

	// Build enrollment request
	payload := tmfifo.EnrollRequestPayload{
		Hostname: c.hostname,
		Posture:  posture,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", "", fmt.Errorf("marshal enroll payload: %w", err)
	}

	req := tmfifo.Message{
		Type:    tmfifo.TypeEnrollRequest,
		Payload: payloadBytes,
		ID:      generateNonce(),
	}

	// Send request
	if err := c.sendMessage(&req); err != nil {
		return "", "", fmt.Errorf("send enroll request: %w", err)
	}

	// Read response
	resp, err := c.readMessage()
	if err != nil {
		return "", "", fmt.Errorf("read enroll response: %w", err)
	}

	if resp.Type != tmfifo.TypeEnrollResponse {
		return "", "", fmt.Errorf("unexpected response type: %s", resp.Type)
	}

	var enrollResp tmfifo.EnrollResponsePayload
	if err := json.Unmarshal(resp.Payload, &enrollResp); err != nil {
		return "", "", fmt.Errorf("parse enroll response: %w", err)
	}

	if !enrollResp.Success {
		return "", "", fmt.Errorf("enrollment failed: %s", enrollResp.Error)
	}

	return enrollResp.HostID, enrollResp.DPUName, nil
}

// ReportPosture sends a posture report to the DPU Agent.
func (c *TmfifoClient) ReportPosture(posture json.RawMessage) error {
	c.connMu.Lock()
	conn := c.conn
	c.connMu.Unlock()

	if conn == nil {
		return fmt.Errorf("tmfifo not open")
	}

	return c.reportPostureWithReader(posture, conn, conn)
}

// reportPostureWithReader is the internal implementation that allows injection of reader/writer for testing.
func (c *TmfifoClient) reportPostureWithReader(posture json.RawMessage, reader io.Reader, writer io.Writer) error {
	payload := tmfifo.PostureReportPayload{
		Hostname: c.hostname,
		Posture:  posture,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal posture payload: %w", err)
	}

	req := tmfifo.Message{
		Type:    tmfifo.TypePostureReport,
		Payload: payloadBytes,
		ID:      generateNonce(),
	}

	// Send posture report
	reqData, err := json.Marshal(&req)
	if err != nil {
		return fmt.Errorf("marshal posture request: %w", err)
	}
	reqData = append(reqData, '\n')
	if _, err := writer.Write(reqData); err != nil {
		return fmt.Errorf("send posture report: %w", err)
	}

	// Read messages until we get the PostureAck
	// The DPU may send CREDENTIAL_PUSH messages before the ack
	bufReader := bufio.NewReader(reader)
	for {
		line, err := bufReader.ReadBytes('\n')
		if err != nil {
			return fmt.Errorf("read posture ack: %w", err)
		}

		var resp tmfifo.Message
		if err := json.Unmarshal(line, &resp); err != nil {
			return fmt.Errorf("parse message: %w", err)
		}

		// Handle CREDENTIAL_PUSH inline
		if resp.Type == tmfifo.TypeCredentialPush {
			if err := c.handleCredentialPushWithWriter(&resp, writer); err != nil {
				log.Printf("credential push handling failed: %v", err)
			}
			continue // Keep waiting for ack
		}

		// Check for expected ack
		if resp.Type != tmfifo.TypePostureAck {
			return fmt.Errorf("unexpected response type: %s", resp.Type)
		}

		var ack tmfifo.PostureAckPayload
		if err := json.Unmarshal(resp.Payload, &ack); err != nil {
			return fmt.Errorf("parse posture ack: %w", err)
		}

		if !ack.Accepted {
			return fmt.Errorf("posture rejected: %s", ack.Error)
		}

		return nil
	}
}

// handleCredentialPushWithWriter processes a CREDENTIAL_PUSH message and sends ack via the provided writer.
func (c *TmfifoClient) handleCredentialPushWithWriter(msg *tmfifo.Message, writer io.Writer) error {
	var payload tmfifo.CredentialPushPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return c.sendCredentialAckWithWriter(false, "", fmt.Sprintf("parse error: %v", err), writer)
	}

	log.Printf("tmfifo: received credential push: type=%s, name=%s",
		payload.CredentialType, payload.CredentialName)

	var installedPath string
	var err error

	switch payload.CredentialType {
	case "ssh-ca":
		result, installErr := c.credInstaller.InstallSSHCA(payload.CredentialName, payload.Data)
		if installErr != nil {
			err = installErr
		} else {
			installedPath = result.InstalledPath
			log.Printf("tmfifo: SSH CA installed at %s (sshd_reloaded=%v, config_updated=%v)",
				result.InstalledPath, result.SshdReloaded, result.ConfigUpdated)
		}
	default:
		err = fmt.Errorf("unsupported credential type: %s", payload.CredentialType)
	}

	if err != nil {
		log.Printf("tmfifo: credential installation failed: %v", err)
		return c.sendCredentialAckWithWriter(false, "", err.Error(), writer)
	}

	return c.sendCredentialAckWithWriter(true, installedPath, "", writer)
}

// sendCredentialAckWithWriter sends a CREDENTIAL_ACK response via the provided writer.
func (c *TmfifoClient) sendCredentialAckWithWriter(success bool, installedPath, errMsg string, writer io.Writer) error {
	payload := tmfifo.CredentialAckPayload{
		Success:       success,
		InstalledPath: installedPath,
		Error:         errMsg,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal credential ack: %w", err)
	}

	msg := tmfifo.Message{
		Type:    tmfifo.TypeCredentialAck,
		Payload: payloadBytes,
		ID:      generateNonce(),
	}

	data, err := json.Marshal(&msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}
	data = append(data, '\n')
	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("write credential ack: %w", err)
	}

	return nil
}

// StartListener starts a goroutine to listen for incoming messages (CREDENTIAL_PUSH).
func (c *TmfifoClient) StartListener() error {
	c.connMu.Lock()
	conn := c.conn
	c.connMu.Unlock()

	if conn == nil {
		return fmt.Errorf("tmfifo not open")
	}

	c.stopCh = make(chan struct{})
	c.wg.Add(1)
	go c.listenLoop()

	return nil
}

// listenLoop continuously reads messages from tmfifo.
func (c *TmfifoClient) listenLoop() {
	defer c.wg.Done()

	c.connMu.Lock()
	conn := c.conn
	c.connMu.Unlock()

	if conn == nil {
		return
	}

	reader := bufio.NewReaderSize(conn, maxMessageSize)

	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		// Read message
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			select {
			case <-c.stopCh:
				return
			default:
				log.Printf("tmfifo read error: %v", err)
				time.Sleep(time.Second)
				continue
			}
		}

		if len(line) == 0 {
			continue
		}

		// Parse message
		var msg tmfifo.Message
		if err := json.Unmarshal(line, &msg); err != nil {
			log.Printf("tmfifo parse error: %v", err)
			continue
		}

		// Handle message
		if err := c.handleMessage(&msg); err != nil {
			log.Printf("tmfifo handle error: %v", err)
		}
	}
}

// handleMessage dispatches incoming messages to appropriate handlers.
func (c *TmfifoClient) handleMessage(msg *tmfifo.Message) error {
	switch msg.Type {
	case tmfifo.TypeCredentialPush:
		return c.handleCredentialPush(msg)
	default:
		log.Printf("tmfifo: ignoring unknown message type: %s", msg.Type)
		return nil
	}
}

// handleCredentialPush processes a CREDENTIAL_PUSH message from the DPU Agent.
func (c *TmfifoClient) handleCredentialPush(msg *tmfifo.Message) error {
	var payload tmfifo.CredentialPushPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return c.sendCredentialAck(false, "", fmt.Sprintf("parse error: %v", err))
	}

	log.Printf("tmfifo: received credential push: type=%s, name=%s",
		payload.CredentialType, payload.CredentialName)

	var installedPath string
	var err error

	switch payload.CredentialType {
	case "ssh-ca":
		result, installErr := c.credInstaller.InstallSSHCA(payload.CredentialName, payload.Data)
		if installErr != nil {
			err = installErr
		} else {
			installedPath = result.InstalledPath
			log.Printf("tmfifo: SSH CA installed at %s (sshd_reloaded=%v, config_updated=%v)",
				result.InstalledPath, result.SshdReloaded, result.ConfigUpdated)
		}
	default:
		err = fmt.Errorf("unsupported credential type: %s", payload.CredentialType)
	}

	if err != nil {
		log.Printf("tmfifo: credential installation failed: %v", err)
		return c.sendCredentialAck(false, "", err.Error())
	}

	return c.sendCredentialAck(true, installedPath, "")
}

// sendCredentialAck sends a CREDENTIAL_ACK response.
func (c *TmfifoClient) sendCredentialAck(success bool, installedPath, errMsg string) error {
	payload := tmfifo.CredentialAckPayload{
		Success:       success,
		InstalledPath: installedPath,
		Error:         errMsg,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal credential ack: %w", err)
	}

	msg := tmfifo.Message{
		Type:    tmfifo.TypeCredentialAck,
		Payload: payloadBytes,
		ID:      generateNonce(),
	}

	return c.sendMessage(&msg)
}

// sendMessage writes a message to the tmfifo connection.
func (c *TmfifoClient) sendMessage(msg *tmfifo.Message) error {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("tmfifo not open")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	// Append newline delimiter
	data = append(data, '\n')

	if _, err := c.conn.Write(data); err != nil {
		return fmt.Errorf("write to tmfifo: %w", err)
	}

	return nil
}

// readMessage reads a single message from the tmfifo connection.
func (c *TmfifoClient) readMessage() (*tmfifo.Message, error) {
	c.connMu.Lock()
	conn := c.conn
	c.connMu.Unlock()

	if conn == nil {
		return nil, fmt.Errorf("tmfifo not open")
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("read from tmfifo: %w", err)
	}

	var msg tmfifo.Message
	if err := json.Unmarshal(line, &msg); err != nil {
		return nil, fmt.Errorf("parse message: %w", err)
	}

	return &msg, nil
}

// generateNonce creates a random 32-character hex nonce.
func generateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// PostureLoop runs a loop that periodically reports posture via tmfifo.
func (c *TmfifoClient) PostureLoop(interval time.Duration, collectPosture func() json.RawMessage, stopCh <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			posture := collectPosture()
			if err := c.ReportPosture(posture); err != nil {
				log.Printf("tmfifo: posture report failed: %v", err)
			} else {
				log.Printf("tmfifo: posture reported successfully")
			}
		}
	}
}
