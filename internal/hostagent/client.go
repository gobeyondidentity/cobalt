package hostagent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/nmelo/secure-infra/pkg/transport"
)

// Client handles communication with the DPU Agent using the Transport interface.
// It provides high-level methods for enrollment, posture reporting, and credential handling.
type Client struct {
	transport     transport.Transport
	hostname      string
	hostID        string
	dpuName       string
	credInstaller *CredentialInstaller

	stopCh chan struct{}
	wg     sync.WaitGroup
	mu     sync.Mutex
}

// NewClient creates a new Host Agent client using the provided transport.
func NewClient(t transport.Transport, hostname string) *Client {
	return &Client{
		transport:     t,
		hostname:      hostname,
		credInstaller: NewCredentialInstaller(),
		stopCh:        make(chan struct{}),
	}
}

// Connect establishes the transport connection.
func (c *Client) Connect(ctx context.Context) error {
	return c.transport.Connect(ctx)
}

// Close closes the client and its underlying transport.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.stopCh != nil {
		close(c.stopCh)
		c.stopCh = nil
	}
	c.mu.Unlock()

	c.wg.Wait()
	return c.transport.Close()
}

// Enroll sends an enrollment request to the DPU Agent.
// Returns the assigned host ID and DPU name on success.
func (c *Client) Enroll(ctx context.Context, posture json.RawMessage) (hostID, dpuName string, err error) {
	// Build enrollment payload
	payload := EnrollRequestPayload{
		Hostname: c.hostname,
		Posture:  posture,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", "", fmt.Errorf("marshal enroll payload: %w", err)
	}

	req := &transport.Message{
		Type:    transport.MessageEnrollRequest,
		Payload: payloadBytes,
		Nonce:   generateNonce(),
	}

	// Send request
	if err := c.transport.Send(req); err != nil {
		return "", "", fmt.Errorf("send enroll request: %w", err)
	}

	// Read response
	resp, err := c.transport.Recv()
	if err != nil {
		return "", "", fmt.Errorf("read enroll response: %w", err)
	}

	if resp.Type != transport.MessageEnrollResponse {
		return "", "", fmt.Errorf("unexpected response type: %s", resp.Type)
	}

	var enrollResp EnrollResponsePayload
	if err := json.Unmarshal(resp.Payload, &enrollResp); err != nil {
		return "", "", fmt.Errorf("parse enroll response: %w", err)
	}

	if !enrollResp.Success {
		return "", "", fmt.Errorf("enrollment failed: %s", enrollResp.Error)
	}

	c.mu.Lock()
	c.hostID = enrollResp.HostID
	c.dpuName = enrollResp.DPUName
	c.mu.Unlock()

	return enrollResp.HostID, enrollResp.DPUName, nil
}

// ReportPosture sends a posture report to the DPU Agent.
func (c *Client) ReportPosture(posture json.RawMessage) error {
	payload := PostureReportPayload{
		Hostname: c.hostname,
		Posture:  posture,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal posture payload: %w", err)
	}

	req := &transport.Message{
		Type:    transport.MessagePostureReport,
		Payload: payloadBytes,
		Nonce:   generateNonce(),
	}

	if err := c.transport.Send(req); err != nil {
		return fmt.Errorf("send posture report: %w", err)
	}

	// Read ack
	resp, err := c.transport.Recv()
	if err != nil {
		return fmt.Errorf("read posture ack: %w", err)
	}

	if resp.Type != transport.MessagePostureAck {
		return fmt.Errorf("unexpected response type: %s", resp.Type)
	}

	var ack PostureAckPayload
	if err := json.Unmarshal(resp.Payload, &ack); err != nil {
		return fmt.Errorf("parse posture ack: %w", err)
	}

	if !ack.Accepted {
		return fmt.Errorf("posture rejected: %s", ack.Error)
	}

	return nil
}

// StartListener starts a goroutine to listen for incoming messages (CREDENTIAL_PUSH).
func (c *Client) StartListener() {
	c.wg.Add(1)
	go c.listenLoop()
}

// listenLoop continuously reads messages from the transport.
func (c *Client) listenLoop() {
	defer c.wg.Done()

	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		msg, err := c.transport.Recv()
		if err != nil {
			select {
			case <-c.stopCh:
				return
			default:
				log.Printf("transport recv error: %v", err)
				time.Sleep(time.Second)
				continue
			}
		}

		if err := c.handleMessage(msg); err != nil {
			log.Printf("handle message error: %v", err)
		}
	}
}

// handleMessage dispatches incoming messages to appropriate handlers.
func (c *Client) handleMessage(msg *transport.Message) error {
	switch msg.Type {
	case transport.MessageCredentialPush:
		return c.handleCredentialPush(msg)
	default:
		log.Printf("ignoring unknown message type: %s", msg.Type)
		return nil
	}
}

// handleCredentialPush processes a CREDENTIAL_PUSH message.
func (c *Client) handleCredentialPush(msg *transport.Message) error {
	var payload CredentialPushPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return c.sendCredentialAck(false, "", fmt.Sprintf("parse error: %v", err))
	}

	log.Printf("received credential push: type=%s, name=%s",
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
			log.Printf("SSH CA installed at %s (sshd_reloaded=%v, config_updated=%v)",
				result.InstalledPath, result.SshdReloaded, result.ConfigUpdated)
		}
	default:
		err = fmt.Errorf("unsupported credential type: %s", payload.CredentialType)
	}

	if err != nil {
		log.Printf("credential installation failed: %v", err)
		return c.sendCredentialAck(false, "", err.Error())
	}

	return c.sendCredentialAck(true, installedPath, "")
}

// sendCredentialAck sends a CREDENTIAL_ACK response.
func (c *Client) sendCredentialAck(success bool, installedPath, errMsg string) error {
	payload := CredentialAckPayload{
		Success:       success,
		InstalledPath: installedPath,
		Error:         errMsg,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal credential ack: %w", err)
	}

	msg := &transport.Message{
		Type:    transport.MessageCredentialAck,
		Payload: payloadBytes,
		Nonce:   generateNonce(),
	}

	return c.transport.Send(msg)
}

// PostureLoop runs a loop that periodically reports posture.
func (c *Client) PostureLoop(interval time.Duration, collectPosture func() json.RawMessage, stopCh <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			posture := collectPosture()
			if err := c.ReportPosture(posture); err != nil {
				log.Printf("posture report failed: %v", err)
			} else {
				log.Printf("posture reported successfully")
			}
		}
	}
}

// TransportType returns the type of the underlying transport.
func (c *Client) TransportType() transport.TransportType {
	return c.transport.Type()
}

// Payload types for the transport protocol.
// These match the types in internal/agent/tmfifo/types.go for wire compatibility.

// EnrollRequestPayload is the payload for ENROLL_REQUEST messages.
type EnrollRequestPayload struct {
	Hostname string          `json:"hostname"`
	Posture  json.RawMessage `json:"posture,omitempty"`
}

// EnrollResponsePayload is the payload for ENROLL_RESPONSE messages.
type EnrollResponsePayload struct {
	Success bool   `json:"success"`
	HostID  string `json:"host_id,omitempty"`
	DPUName string `json:"dpu_name,omitempty"`
	Error   string `json:"error,omitempty"`
}

// PostureReportPayload is the payload for POSTURE_REPORT messages.
type PostureReportPayload struct {
	Hostname string          `json:"hostname"`
	Posture  json.RawMessage `json:"posture"`
}

// PostureAckPayload is the payload for POSTURE_ACK messages.
type PostureAckPayload struct {
	Accepted bool   `json:"accepted"`
	Error    string `json:"error,omitempty"`
}

// CredentialPushPayload is the payload for CREDENTIAL_PUSH messages.
type CredentialPushPayload struct {
	CredentialType string `json:"credential_type"`
	CredentialName string `json:"credential_name"`
	Data           []byte `json:"data"`
}

// CredentialAckPayload is the payload for CREDENTIAL_ACK messages.
type CredentialAckPayload struct {
	Success       bool   `json:"success"`
	InstalledPath string `json:"installed_path,omitempty"`
	Error         string `json:"error,omitempty"`
}
