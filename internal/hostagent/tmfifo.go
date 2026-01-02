// Package hostagent implements the Host Agent functionality.
package hostagent

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/nmelo/secure-infra/internal/agent/tmfifo"
)

const (
	// DefaultTmfifoPath is the default tmfifo device path on the host side.
	DefaultTmfifoPath = "/dev/tmfifo_net0"

	// tmfifoReadTimeout is the timeout for reading from tmfifo.
	tmfifoReadTimeout = 30 * time.Second

	// maxMessageSize limits the size of tmfifo messages.
	maxMessageSize = 64 * 1024 // 64KB
)

// TmfifoClient handles communication with the DPU Agent over tmfifo.
type TmfifoClient struct {
	devicePath string
	device     *os.File
	deviceMu   sync.Mutex

	credInstaller *CredentialInstaller
	hostname      string

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewTmfifoClient creates a new tmfifo client.
func NewTmfifoClient(devicePath, hostname string) *TmfifoClient {
	if devicePath == "" {
		devicePath = DefaultTmfifoPath
	}
	return &TmfifoClient{
		devicePath:    devicePath,
		hostname:      hostname,
		credInstaller: NewCredentialInstaller(),
		stopCh:        make(chan struct{}),
	}
}

// DetectTmfifo checks if the tmfifo device exists.
// Returns the device path and true if available.
func DetectTmfifo() (string, bool) {
	path := DefaultTmfifoPath
	if _, err := os.Stat(path); err == nil {
		return path, true
	}
	return "", false
}

// Open opens the tmfifo device for communication.
func (c *TmfifoClient) Open() error {
	c.deviceMu.Lock()
	defer c.deviceMu.Unlock()

	if c.device != nil {
		return nil // Already open
	}

	f, err := os.OpenFile(c.devicePath, os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open tmfifo device %s: %w", c.devicePath, err)
	}
	c.device = f
	return nil
}

// Close closes the tmfifo device.
func (c *TmfifoClient) Close() error {
	c.deviceMu.Lock()
	defer c.deviceMu.Unlock()

	if c.device == nil {
		return nil
	}

	// Signal stop to listener
	close(c.stopCh)
	c.wg.Wait()

	err := c.device.Close()
	c.device = nil
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
		Nonce:   generateNonce(),
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
	if c.device == nil {
		return fmt.Errorf("tmfifo not open")
	}

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
		Nonce:   generateNonce(),
	}

	if err := c.sendMessage(&req); err != nil {
		return fmt.Errorf("send posture report: %w", err)
	}

	// Read ack
	resp, err := c.readMessage()
	if err != nil {
		return fmt.Errorf("read posture ack: %w", err)
	}

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

// StartListener starts a goroutine to listen for incoming messages (CREDENTIAL_PUSH).
func (c *TmfifoClient) StartListener() error {
	if c.device == nil {
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

	reader := bufio.NewReaderSize(c.device, maxMessageSize)

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
		Nonce:   generateNonce(),
	}

	return c.sendMessage(&msg)
}

// sendMessage writes a message to the tmfifo device.
func (c *TmfifoClient) sendMessage(msg *tmfifo.Message) error {
	c.deviceMu.Lock()
	defer c.deviceMu.Unlock()

	if c.device == nil {
		return fmt.Errorf("tmfifo not open")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	// Append newline delimiter
	data = append(data, '\n')

	if _, err := c.device.Write(data); err != nil {
		return fmt.Errorf("write to tmfifo: %w", err)
	}

	return nil
}

// readMessage reads a single message from the tmfifo device.
func (c *TmfifoClient) readMessage() (*tmfifo.Message, error) {
	c.deviceMu.Lock()
	defer c.deviceMu.Unlock()

	if c.device == nil {
		return nil, fmt.Errorf("tmfifo not open")
	}

	reader := bufio.NewReader(c.device)
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
