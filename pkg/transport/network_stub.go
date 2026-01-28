package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"sync"
)

// networkTransport implements Transport using HTTP/mTLS for non-BlueField deployments.
// This transport is used when hardware transports (DOCA Comch, tmfifo) are unavailable.
type networkTransport struct {
	dpuAddr    string
	inviteCode string
	tlsConfig  *tls.Config
	hostname   string

	connected bool
	closed    bool
	mu        sync.Mutex

	// pendingRecv holds messages received from the server that haven't been read yet.
	// In a full implementation, this would be a bidirectional channel (e.g., WebSocket).
	// For now, the network transport is primarily request/response based.
	pendingRecv chan *Message
}

// NewNetworkTransport creates a transport using mTLS over TCP.
// The hostname is used for identification during enrollment.
func NewNetworkTransport(addr, inviteCode string, tlsConfig *tls.Config, hostname string) (Transport, error) {
	return &networkTransport{
		dpuAddr:     addr,
		inviteCode:  inviteCode,
		tlsConfig:   tlsConfig,
		hostname:    hostname,
		pendingRecv: make(chan *Message, 10),
	}, nil
}

// Connect establishes the network connection.
func (n *networkTransport) Connect(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.closed {
		return fmt.Errorf("transport closed")
	}

	// For HTTP-based transport, we don't maintain a persistent connection.
	// Each Send/Recv is a separate HTTP request.
	n.connected = true
	return nil
}

// Send transmits a message over the network.
// Note: The current network mode uses specific REST endpoints, not a generic message protocol.
// This implementation is a placeholder for future bidirectional protocol support.
func (n *networkTransport) Send(msg *Message) error {
	n.mu.Lock()
	if !n.connected {
		n.mu.Unlock()
		return fmt.Errorf("transport not connected")
	}
	n.mu.Unlock()

	// The network transport currently doesn't support arbitrary message sending
	// in the same way as tmfifo. The Host Agent uses specific HTTP endpoints
	// for register and posture when using network transport.
	// This will be fully implemented when the transport protocol is unified.
	return fmt.Errorf("NetworkTransport.Send not implemented for message type %s", msg.Type)
}

// Recv receives a message from the network.
// HTTP is request/response based, so Recv blocks waiting for queued responses.
func (n *networkTransport) Recv() (*Message, error) {
	n.mu.Lock()
	if !n.connected {
		n.mu.Unlock()
		return nil, fmt.Errorf("transport not connected")
	}
	n.mu.Unlock()

	msg, ok := <-n.pendingRecv
	if !ok {
		return nil, io.EOF
	}
	return msg, nil
}

// Close closes the network transport.
func (n *networkTransport) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.closed {
		return nil
	}

	n.closed = true
	n.connected = false
	close(n.pendingRecv)
	return nil
}

// Reset clears the closed state, allowing the transport to reconnect.
func (n *networkTransport) Reset() {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.closed = false
	n.connected = false
	n.pendingRecv = make(chan *Message, 10)
}

// Type returns TransportNetwork.
func (n *networkTransport) Type() TransportType {
	return TransportNetwork
}

// DPUAddr returns the DPU Agent address.
func (n *networkTransport) DPUAddr() string {
	return n.dpuAddr
}

// Hostname returns the hostname.
func (n *networkTransport) Hostname() string {
	return n.hostname
}

// QueueResponse adds a response message to the pending receive queue.
// This bridges HTTP responses to the Transport interface.
func (n *networkTransport) QueueResponse(msg *Message) error {
	select {
	case n.pendingRecv <- msg:
		return nil
	default:
		return fmt.Errorf("response queue full")
	}
}

// ============================================================================
// Network Listener
// ============================================================================

// NetworkListener implements TransportListener for TCP-based connections.
// Used by DPU agents as a fallback when hardware transports are unavailable.
type NetworkListener struct {
	listener  interface{ Close() error }
	addr      string
	tlsConfig *tls.Config
	closed    bool
	mu        sync.Mutex

	// acceptCh delivers accepted connections
	acceptCh chan Transport
	// doneCh signals shutdown
	doneCh chan struct{}
}

// NewNetworkListener creates a listener for TCP connections on the specified address.
// The address should be in "host:port" format (e.g., ":18052" or "0.0.0.0:18052").
func NewNetworkListener(addr string, tlsConfig *tls.Config) (*NetworkListener, error) {
	if addr == "" {
		return nil, fmt.Errorf("network listener: address required")
	}

	l := &NetworkListener{
		addr:      addr,
		tlsConfig: tlsConfig,
		acceptCh:  make(chan Transport, 10),
		doneCh:    make(chan struct{}),
	}

	// Note: In a full implementation, this would call net.Listen() and start
	// an accept loop. For now, we provide a stub that can be used for testing
	// and will be filled in when the network transport is fully implemented.

	return l, nil
}

// Accept blocks until a new client connection is received.
// Returns a Transport for communicating with the connected client.
func (l *NetworkListener) Accept() (Transport, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, fmt.Errorf("listener closed")
	}
	l.mu.Unlock()

	select {
	case t := <-l.acceptCh:
		return t, nil
	case <-l.doneCh:
		return nil, fmt.Errorf("listener closed")
	}
}

// Close stops the listener and releases resources.
func (l *NetworkListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}

	l.closed = true
	close(l.doneCh)

	if l.listener != nil {
		return l.listener.Close()
	}
	return nil
}

// Type returns TransportNetwork.
func (l *NetworkListener) Type() TransportType {
	return TransportNetwork
}

// Addr returns the listen address.
func (l *NetworkListener) Addr() string {
	return l.addr
}

// QueueConnection allows tests to inject a transport as if it were accepted.
// This is primarily for testing purposes.
func (l *NetworkListener) QueueConnection(t Transport) error {
	select {
	case l.acceptCh <- t:
		return nil
	default:
		return fmt.Errorf("accept queue full")
	}
}
