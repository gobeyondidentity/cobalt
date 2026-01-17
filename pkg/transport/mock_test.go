package transport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"
)

func TestMockTransport_BasicSendRecv(t *testing.T) {
	// Create two mock transports to simulate Host and DPU
	hostTransport := NewMockTransport()
	dpuTransport := NewMockTransport()

	ctx := context.Background()

	// Connect both
	if err := hostTransport.Connect(ctx); err != nil {
		t.Fatalf("host connect failed: %v", err)
	}
	if err := dpuTransport.Connect(ctx); err != nil {
		t.Fatalf("dpu connect failed: %v", err)
	}

	// Create a test message
	payload, _ := json.Marshal(map[string]string{"hostname": "test-host"})
	msg := &Message{
		Type:    MessageEnrollRequest,
		Payload: payload,
		Nonce:   "test-nonce-123",
	}

	// Host sends message
	if err := hostTransport.Send(msg); err != nil {
		t.Fatalf("send failed: %v", err)
	}

	// Dequeue from host's send channel (simulating DPU receiving)
	received, err := hostTransport.Dequeue()
	if err != nil {
		t.Fatalf("dequeue failed: %v", err)
	}

	// Verify message contents
	if received.Type != MessageEnrollRequest {
		t.Errorf("expected type %s, got %s", MessageEnrollRequest, received.Type)
	}
	if received.Nonce != "test-nonce-123" {
		t.Errorf("expected nonce test-nonce-123, got %s", received.Nonce)
	}

	// Verify message was recorded
	sent := hostTransport.SentMessages()
	if len(sent) != 1 {
		t.Errorf("expected 1 sent message, got %d", len(sent))
	}

	// DPU enqueues a response for host to receive
	responsePayload, _ := json.Marshal(map[string]string{"host_id": "host-001"})
	response := &Message{
		Type:    MessageEnrollResponse,
		Payload: responsePayload,
		Nonce:   "response-nonce-456",
	}

	if err := hostTransport.Enqueue(response); err != nil {
		t.Fatalf("enqueue failed: %v", err)
	}

	// Host receives the response
	recvMsg, err := hostTransport.Recv()
	if err != nil {
		t.Fatalf("recv failed: %v", err)
	}

	if recvMsg.Type != MessageEnrollResponse {
		t.Errorf("expected type %s, got %s", MessageEnrollResponse, recvMsg.Type)
	}

	// Verify received message was recorded
	recvd := hostTransport.ReceivedMessages()
	if len(recvd) != 1 {
		t.Errorf("expected 1 received message, got %d", len(recvd))
	}

	// Clean up
	hostTransport.Close()
	dpuTransport.Close()
}

func TestMockTransport_Type(t *testing.T) {
	m := NewMockTransport()
	if m.Type() != TransportMock {
		t.Errorf("expected type %s, got %s", TransportMock, m.Type())
	}
}

func TestMockTransport_ErrorInjection(t *testing.T) {
	m := NewMockTransport(WithSendError(errors.New("simulated send error")))

	ctx := context.Background()
	if err := m.Connect(ctx); err != nil {
		t.Fatalf("connect failed: %v", err)
	}

	// Send should return the injected error
	err := m.Send(&Message{Type: MessagePostureReport})
	if err == nil {
		t.Error("expected send error, got nil")
	}
	if err.Error() != "simulated send error" {
		t.Errorf("expected 'simulated send error', got '%s'", err.Error())
	}

	// Test recv error injection
	m2 := NewMockTransport(WithRecvError(errors.New("simulated recv error")))
	if err := m2.Connect(ctx); err != nil {
		t.Fatalf("connect failed: %v", err)
	}

	_, err = m2.Recv()
	if err == nil {
		t.Error("expected recv error, got nil")
	}
	if err.Error() != "simulated recv error" {
		t.Errorf("expected 'simulated recv error', got '%s'", err.Error())
	}
}

func TestMockTransport_Latency(t *testing.T) {
	latency := 50 * time.Millisecond
	m := NewMockTransport(WithLatency(latency))

	ctx := context.Background()
	if err := m.Connect(ctx); err != nil {
		t.Fatalf("connect failed: %v", err)
	}

	// Pre-enqueue a message for recv
	m.Enqueue(&Message{Type: MessagePostureAck})

	// Time the recv operation
	start := time.Now()
	_, err := m.Recv()
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("recv failed: %v", err)
	}

	// Should take at least the configured latency
	if elapsed < latency {
		t.Errorf("expected latency >= %v, got %v", latency, elapsed)
	}
}

func TestMockTransport_ConnectErrors(t *testing.T) {
	// Test custom connect function
	expectedErr := errors.New("connection refused")
	m := NewMockTransport(WithConnectFunc(func(ctx context.Context) error {
		return expectedErr
	}))

	err := m.Connect(context.Background())
	if err != expectedErr {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

func TestMockTransport_CloseAndEOF(t *testing.T) {
	m := NewMockTransport()

	ctx := context.Background()
	if err := m.Connect(ctx); err != nil {
		t.Fatalf("connect failed: %v", err)
	}

	// Close the transport
	if err := m.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	// Recv should return EOF
	_, err := m.Recv()
	if err != io.EOF {
		t.Errorf("expected io.EOF after close, got %v", err)
	}

	// Send should fail
	err = m.Send(&Message{Type: MessagePostureReport})
	if err == nil {
		t.Error("expected error on send after close")
	}

	// Double close should be safe
	if err := m.Close(); err != nil {
		t.Errorf("double close should not error: %v", err)
	}
}

func TestMockTransport_NotConnected(t *testing.T) {
	m := NewMockTransport()

	// Send without connect should fail
	err := m.Send(&Message{Type: MessagePostureReport})
	if err == nil {
		t.Error("expected error when not connected")
	}

	// Recv without connect should fail
	_, err = m.Recv()
	if err == nil {
		t.Error("expected error when not connected")
	}
}

func TestMockTransport_StateHelpers(t *testing.T) {
	m := NewMockTransport()

	if m.IsConnected() {
		t.Error("should not be connected initially")
	}
	if m.IsClosed() {
		t.Error("should not be closed initially")
	}

	m.Connect(context.Background())

	if !m.IsConnected() {
		t.Error("should be connected after Connect")
	}

	m.Close()

	if m.IsConnected() {
		t.Error("should not be connected after Close")
	}
	if !m.IsClosed() {
		t.Error("should be closed after Close")
	}
}

func TestMockTransport_ClearRecords(t *testing.T) {
	m := NewMockTransport()
	m.Connect(context.Background())

	// Send some messages
	m.Send(&Message{Type: MessagePostureReport, Nonce: "1"})
	m.Send(&Message{Type: MessagePostureReport, Nonce: "2"})

	if len(m.SentMessages()) != 2 {
		t.Errorf("expected 2 sent messages, got %d", len(m.SentMessages()))
	}

	// Clear records
	m.ClearRecords()

	if len(m.SentMessages()) != 0 {
		t.Errorf("expected 0 sent messages after clear, got %d", len(m.SentMessages()))
	}
}

func TestMockTransport_DynamicErrorInjection(t *testing.T) {
	m := NewMockTransport()
	m.Connect(context.Background())

	// Initially no error
	if err := m.Send(&Message{Type: MessagePostureReport}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Inject error dynamically
	m.SetSendError(errors.New("injected error"))

	err := m.Send(&Message{Type: MessagePostureReport})
	if err == nil || err.Error() != "injected error" {
		t.Errorf("expected 'injected error', got %v", err)
	}

	// Clear the error
	m.SetSendError(nil)

	if err := m.Send(&Message{Type: MessagePostureReport}); err != nil {
		t.Errorf("expected no error after clearing, got %v", err)
	}
}
