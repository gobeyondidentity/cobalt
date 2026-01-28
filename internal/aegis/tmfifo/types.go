// Package tmfifo provides communication with the Host Agent over the BlueField tmfifo device.
// tmfifo is a memory-mapped FIFO that allows the DPU ARM cores to communicate with
// the host x86 system without using the network stack.
package tmfifo

import "encoding/json"

// ProtocolVersion is the current protocol version for message envelopes.
const ProtocolVersion uint8 = 1

// Message is the wire format for tmfifo protocol messages.
// All communication between DPU Agent and Host Agent uses this envelope.
type Message struct {
	Version uint8           `json:"v"`
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	TS      int64           `json:"ts"`
	Payload json.RawMessage `json:"payload"`
}

// Message types for the tmfifo protocol.
const (
	// TypeEnrollRequest is sent by Host Agent to register with the DPU.
	TypeEnrollRequest = "ENROLL_REQUEST"

	// TypeEnrollResponse is sent by DPU Agent in response to enrollment.
	TypeEnrollResponse = "ENROLL_RESPONSE"

	// TypePostureReport is sent by Host Agent to update security posture.
	TypePostureReport = "POSTURE_REPORT"

	// TypePostureAck is sent by DPU Agent to acknowledge posture update.
	TypePostureAck = "POSTURE_ACK"

	// TypeCredentialPush is sent by DPU Agent to distribute credentials to the host.
	TypeCredentialPush = "CREDENTIAL_PUSH"

	// TypeCredentialAck is sent by Host Agent to acknowledge credential receipt.
	TypeCredentialAck = "CREDENTIAL_ACK"
)

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
	CredentialType string `json:"credential_type"` // "ssh-ca", "tls-cert", etc.
	CredentialName string `json:"credential_name"`
	Data           []byte `json:"data"` // Public key or certificate
}

// CredentialAckPayload is the payload for CREDENTIAL_ACK messages.
type CredentialAckPayload struct {
	Success       bool   `json:"success"`
	InstalledPath string `json:"installed_path,omitempty"`
	Error         string `json:"error,omitempty"`
}
