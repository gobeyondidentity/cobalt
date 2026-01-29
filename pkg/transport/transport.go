// Package transport defines the Transport interface for Host-DPU communication.
// This abstraction allows multiple transport implementations (DOCA Comch, tmfifo_net,
// network, mock) to be used interchangeably based on hardware availability.
package transport

import (
	"context"
	"encoding/json"
)

// TransportType identifies the underlying transport mechanism.
type TransportType string

const (
	// TransportDOCAComch uses NVIDIA DOCA Comch for BlueField DPU communication.
	// This is the preferred production transport on systems with BlueField hardware.
	TransportDOCAComch TransportType = "doca_comch"

	// TransportTmfifoNet uses the tmfifo_net0 device for legacy BlueField communication.
	// Preserves compatibility with socat-based emulator tests.
	TransportTmfifoNet TransportType = "tmfifo_net"

	// TransportNetwork uses mTLS over TCP for non-BlueField deployments.
	// Requires invite code authentication; less secure than hardware transports.
	TransportNetwork TransportType = "network"

	// TransportMock provides an in-memory transport for unit testing.
	// Supports message recording and configurable latency/error injection.
	TransportMock TransportType = "mock"
)

// Transport defines the interface for Host-DPU communication.
// Implementations handle the underlying protocol (DOCA Comch, tmfifo, TCP, etc.)
// while presenting a uniform message-passing interface.
type Transport interface {
	// Connect establishes the transport connection.
	// For client transports (Host Agent), this connects to the DPU.
	// Returns an error if the connection cannot be established.
	Connect(ctx context.Context) error

	// Send transmits a message over the transport.
	// The message is serialized according to the transport's wire format.
	Send(msg *Message) error

	// Recv blocks until a message is received or an error occurs.
	// Returns the received message or an error (including io.EOF on close).
	Recv() (*Message, error)

	// Close terminates the transport connection and releases resources.
	Close() error

	// Type returns the transport type identifier.
	Type() TransportType
}

// Resettable is an optional interface for transports that support reconnection.
// Transports implementing this interface can be reset after Close() to allow
// re-establishing the connection without creating a new transport instance.
// Used by sentry for automatic reconnection after aegis restarts.
type Resettable interface {
	// Reset clears the closed state, allowing the transport to reconnect.
	// Must be called after Close() and before Connect().
	Reset()
}

// TransportListener defines the server-side interface for accepting connections.
// Used by the DPU Agent to accept incoming Host Agent connections.
type TransportListener interface {
	// Accept blocks until a new connection is received.
	// Returns a Transport for communicating with the connected client.
	Accept() (Transport, error)

	// Close stops the listener and releases resources.
	Close() error

	// Type returns the transport type this listener accepts.
	Type() TransportType
}

// MessageType identifies the type of protocol message.
type MessageType string

const (
	// MessageEnrollRequest is sent by Host Agent to register with the DPU.
	MessageEnrollRequest MessageType = "ENROLL_REQUEST"

	// MessageEnrollResponse is sent by DPU Agent in response to enrollment.
	MessageEnrollResponse MessageType = "ENROLL_RESPONSE"

	// MessagePostureReport is sent by Host Agent to update security posture.
	MessagePostureReport MessageType = "POSTURE_REPORT"

	// MessagePostureAck is sent by DPU Agent to acknowledge posture update.
	MessagePostureAck MessageType = "POSTURE_ACK"

	// MessageCredentialPush is sent by DPU Agent to distribute credentials to the host.
	MessageCredentialPush MessageType = "CREDENTIAL_PUSH"

	// MessageCredentialAck is sent by Host Agent to acknowledge credential receipt.
	MessageCredentialAck MessageType = "CREDENTIAL_ACK"

	// MessageCertRequest is sent by Host Agent to request a certificate from the DPU.
	MessageCertRequest MessageType = "CERT_REQUEST"

	// MessageCertResponse is sent by DPU Agent with the requested certificate.
	MessageCertResponse MessageType = "CERT_RESPONSE"

	// Authentication message types (must exchange before any other messages)

	// MessageAuthChallenge is sent by DPU immediately on connection.
	MessageAuthChallenge MessageType = "AUTH_CHALLENGE"

	// MessageAuthResponse is sent by Host to prove identity.
	MessageAuthResponse MessageType = "AUTH_RESPONSE"

	// MessageAuthOK indicates successful authentication.
	MessageAuthOK MessageType = "AUTH_OK"

	// MessageAuthFail indicates authentication failure.
	MessageAuthFail MessageType = "AUTH_FAIL"
)

// ProtocolVersion is the current protocol version for message envelopes.
const ProtocolVersion uint8 = 1

// Tmfifo TCP transport constants.
// The tmfifo_net0 interface is a network interface (not a character device) that provides
// IP connectivity between the BlueField DPU ARM cores and the host x86 system.
// We use TCP sockets over this interface for reliable message delivery.
const (
	// TmfifoListenPort is the TCP port aegis listens on for tmfifo connections.
	TmfifoListenPort = 9444

	// TmfifoDefaultDPUAddr is the default DPU address for tmfifo TCP connections.
	// This is the standard IP assigned to the DPU side of the tmfifo_net0 interface.
	TmfifoDefaultDPUAddr = "192.168.100.2:9444"

	// TmfifoInterfaceName is the network interface name for tmfifo communication.
	TmfifoInterfaceName = "tmfifo_net0"
)

// Message is the wire format for transport protocol messages.
// All communication between DPU Agent and Host Agent uses this envelope.
type Message struct {
	// Version is the protocol version. Current: 1
	Version uint8 `json:"v"`

	// Type identifies the message type (e.g., ENROLL_REQUEST, POSTURE_REPORT).
	Type MessageType `json:"type"`

	// ID is the correlation ID (UUID v4). Request and response share the same ID.
	ID string `json:"id"`

	// TS is the sender's Unix timestamp in milliseconds.
	TS int64 `json:"ts"`

	// Payload contains the message-specific data as JSON.
	Payload json.RawMessage `json:"payload"`
}
