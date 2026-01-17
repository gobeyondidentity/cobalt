package transport

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

// MockTransport provides an in-memory Transport implementation for testing.
// It supports message recording, configurable latency, and error injection.
type MockTransport struct {
	// sendCh receives messages sent via Send() for the peer to receive
	sendCh chan *Message
	// recvCh provides messages for Recv() to return
	recvCh chan *Message

	// Configuration
	latency   time.Duration
	sendErr   error
	recvErr   error
	connectFn func(ctx context.Context) error

	// State
	connected bool
	closed    bool
	mu        sync.Mutex

	// Recording for test inspection
	sentMessages     []*Message
	receivedMessages []*Message
	recordMu         sync.Mutex
}

// MockTransportOption configures a MockTransport.
type MockTransportOption func(*MockTransport)

// WithLatency adds simulated latency to Send and Recv operations.
func WithLatency(d time.Duration) MockTransportOption {
	return func(m *MockTransport) {
		m.latency = d
	}
}

// WithSendError injects an error that will be returned by Send.
func WithSendError(err error) MockTransportOption {
	return func(m *MockTransport) {
		m.sendErr = err
	}
}

// WithRecvError injects an error that will be returned by Recv.
func WithRecvError(err error) MockTransportOption {
	return func(m *MockTransport) {
		m.recvErr = err
	}
}

// WithConnectFunc sets a custom connect function for testing connection logic.
func WithConnectFunc(fn func(ctx context.Context) error) MockTransportOption {
	return func(m *MockTransport) {
		m.connectFn = fn
	}
}

// WithBufferSize sets the channel buffer size (default: 100).
func WithBufferSize(size int) MockTransportOption {
	return func(m *MockTransport) {
		m.sendCh = make(chan *Message, size)
		m.recvCh = make(chan *Message, size)
	}
}

// NewMockTransport creates a new MockTransport for testing.
// The returned transport has buffered channels for send/recv operations.
func NewMockTransport(opts ...MockTransportOption) *MockTransport {
	m := &MockTransport{
		sendCh:           make(chan *Message, 100),
		recvCh:           make(chan *Message, 100),
		sentMessages:     make([]*Message, 0),
		receivedMessages: make([]*Message, 0),
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// Connect establishes the mock connection.
// If a custom connect function was provided, it is called.
func (m *MockTransport) Connect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("transport closed")
	}

	if m.connectFn != nil {
		if err := m.connectFn(ctx); err != nil {
			return err
		}
	}

	m.connected = true
	return nil
}

// Send transmits a message to the peer.
// The message is placed on the send channel and recorded for inspection.
func (m *MockTransport) Send(msg *Message) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errors.New("transport closed")
	}
	if !m.connected {
		m.mu.Unlock()
		return errors.New("transport not connected")
	}
	sendErr := m.sendErr
	latency := m.latency
	m.mu.Unlock()

	if sendErr != nil {
		return sendErr
	}

	if latency > 0 {
		time.Sleep(latency)
	}

	// Record the message
	m.recordMu.Lock()
	m.sentMessages = append(m.sentMessages, msg)
	m.recordMu.Unlock()

	// Send to channel (non-blocking with timeout to prevent deadlock in tests)
	select {
	case m.sendCh <- msg:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("send channel full")
	}
}

// Recv receives a message from the peer.
// Returns io.EOF if the transport is closed.
func (m *MockTransport) Recv() (*Message, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, io.EOF
	}
	if !m.connected {
		m.mu.Unlock()
		return nil, errors.New("transport not connected")
	}
	recvErr := m.recvErr
	latency := m.latency
	m.mu.Unlock()

	if recvErr != nil {
		return nil, recvErr
	}

	if latency > 0 {
		time.Sleep(latency)
	}

	msg, ok := <-m.recvCh
	if !ok {
		return nil, io.EOF
	}
	// Record the message
	m.recordMu.Lock()
	m.receivedMessages = append(m.receivedMessages, msg)
	m.recordMu.Unlock()
	return msg, nil
}

// Close terminates the mock connection.
func (m *MockTransport) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true
	m.connected = false
	close(m.sendCh)
	close(m.recvCh)
	return nil
}

// Type returns TransportMock.
func (m *MockTransport) Type() TransportType {
	return TransportMock
}

// --- Test inspection methods ---

// SentMessages returns all messages sent via Send().
func (m *MockTransport) SentMessages() []*Message {
	m.recordMu.Lock()
	defer m.recordMu.Unlock()
	result := make([]*Message, len(m.sentMessages))
	copy(result, m.sentMessages)
	return result
}

// ReceivedMessages returns all messages received via Recv().
func (m *MockTransport) ReceivedMessages() []*Message {
	m.recordMu.Lock()
	defer m.recordMu.Unlock()
	result := make([]*Message, len(m.receivedMessages))
	copy(result, m.receivedMessages)
	return result
}

// ClearRecords clears the recorded sent and received messages.
func (m *MockTransport) ClearRecords() {
	m.recordMu.Lock()
	defer m.recordMu.Unlock()
	m.sentMessages = m.sentMessages[:0]
	m.receivedMessages = m.receivedMessages[:0]
}

// --- Test helper methods ---

// Enqueue adds a message to the receive channel for Recv() to return.
// Use this to simulate messages from the peer.
func (m *MockTransport) Enqueue(msg *Message) error {
	select {
	case m.recvCh <- msg:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("enqueue timeout: recv channel full")
	}
}

// Dequeue removes and returns the next message from the send channel.
// Use this to inspect messages sent by the code under test.
func (m *MockTransport) Dequeue() (*Message, error) {
	select {
	case msg, ok := <-m.sendCh:
		if !ok {
			return nil, io.EOF
		}
		return msg, nil
	case <-time.After(5 * time.Second):
		return nil, errors.New("dequeue timeout: no message available")
	}
}

// SetSendError updates the error returned by Send.
// Pass nil to clear the error.
func (m *MockTransport) SetSendError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sendErr = err
}

// SetRecvError updates the error returned by Recv.
// Pass nil to clear the error.
func (m *MockTransport) SetRecvError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recvErr = err
}

// SetLatency updates the simulated latency for Send and Recv.
func (m *MockTransport) SetLatency(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.latency = d
}

// IsConnected returns whether the transport is currently connected.
func (m *MockTransport) IsConnected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connected && !m.closed
}

// IsClosed returns whether the transport has been closed.
func (m *MockTransport) IsClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}
