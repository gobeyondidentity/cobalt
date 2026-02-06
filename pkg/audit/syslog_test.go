package audit

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/authz"
)

// testSocketPath returns a short, unique Unix socket path for testing.
// Unix socket paths have a 108-character limit.
func testSocketPath(suffix string) string {
	return fmt.Sprintf("/tmp/syslog_%d_%s.sock", os.Getpid(), suffix)
}

func TestSyslogWriter_MessageDelivery(t *testing.T) {
	t.Log("Testing that LogDecision delivers a valid RFC 5424 message to the socket")

	socketPath := testSocketPath("delivery")
	t.Cleanup(func() { os.Remove(socketPath) })

	// Start mock syslog receiver (datagram socket)
	addr := net.UnixAddr{Name: socketPath, Net: "unixgram"}
	conn, err := net.ListenUnixgram("unixgram", &addr)
	if err != nil {
		t.Fatalf("failed to create mock syslog listener: %v", err)
	}
	defer conn.Close()

	// Create SyslogAuditLogger pointing at mock socket
	writer, err := NewSyslogWriter(SyslogConfig{
		SocketPath: socketPath,
		Hostname:   "test.local",
		AppName:    "nexus",
	})
	if err != nil {
		t.Fatalf("NewSyslogWriter failed: %v", err)
	}
	defer writer.Close()

	// Send an audit event
	ts, _ := time.Parse(time.RFC3339Nano, "2026-02-04T15:30:00.000Z")
	entry := authz.AuthzAuditEntry{
		Timestamp:     ts,
		RequestID:     "req-001",
		Principal:     "km_abc123",
		PrincipalType: "operator",
		Action:        "credential:push",
		Resource:      "/api/v1/push",
		ResourceType:  "endpoint",
		Decision:      "allow",
		Reason:        "DPoP authentication succeeded",
		PolicyID:      "policy-001",
		DurationUS:    1200,
	}

	t.Log("Writing audit event via LogDecision")
	if err := writer.LogDecision(context.Background(), entry); err != nil {
		t.Fatalf("LogDecision failed: %v", err)
	}

	// Read from mock socket
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read from mock socket: %v", err)
	}

	got := string(buf[:n])
	t.Logf("Received message: %s", got)

	// Verify RFC 5424 structure
	if !strings.HasPrefix(got, "<134>1") {
		t.Errorf("expected priority <134>1 (Local0+INFO), got prefix: %s", got[:10])
	}
	if !strings.Contains(got, "test.local") {
		t.Error("hostname 'test.local' not found in message")
	}
	if !strings.Contains(got, "nexus") {
		t.Error("app-name 'nexus' not found in message")
	}
	if !strings.Contains(got, "auth.success") {
		t.Error("event type 'auth.success' not found in MSGID")
	}
	if !strings.Contains(got, `[cobalt`) {
		t.Error("structured data element 'cobalt' not found")
	}
	if !strings.Contains(got, `principal="km_abc123"`) {
		t.Error("principal SD param not found")
	}
	if !strings.Contains(got, `decision="allow"`) {
		t.Error("decision SD param not found")
	}
	if !strings.Contains(got, `request_id="req-001"`) {
		t.Error("request_id SD param not found")
	}
	if !strings.Contains(got, `latency_us="1200"`) {
		t.Error("latency_us SD param not found")
	}
	if !strings.Contains(got, "DPoP authentication succeeded") {
		t.Error("message text not found")
	}
}

func TestSyslogWriter_DenyEvent(t *testing.T) {
	t.Log("Testing that denied decisions produce auth.failure with WARNING severity")

	socketPath := testSocketPath("deny")
	t.Cleanup(func() { os.Remove(socketPath) })

	addr := net.UnixAddr{Name: socketPath, Net: "unixgram"}
	conn, err := net.ListenUnixgram("unixgram", &addr)
	if err != nil {
		t.Fatalf("failed to create mock syslog listener: %v", err)
	}
	defer conn.Close()

	writer, err := NewSyslogWriter(SyslogConfig{
		SocketPath: socketPath,
		Hostname:   "test.local",
		AppName:    "nexus",
	})
	if err != nil {
		t.Fatalf("NewSyslogWriter failed: %v", err)
	}
	defer writer.Close()

	entry := authz.AuthzAuditEntry{
		Timestamp: time.Now(),
		Principal: "km_unknown",
		Action:    "credential:push",
		Resource:  "/api/v1/push",
		Decision:  "deny",
		Reason:    "unauthorized",
	}

	t.Log("Writing deny event")
	if err := writer.LogDecision(context.Background(), entry); err != nil {
		t.Fatalf("LogDecision failed: %v", err)
	}

	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read from mock socket: %v", err)
	}

	got := string(buf[:n])
	t.Logf("Received message: %s", got)

	if !strings.HasPrefix(got, "<132>1") {
		t.Errorf("expected priority <132>1 (Local0+WARNING), got prefix: %s", got[:10])
	}
	if !strings.Contains(got, "auth.failure") {
		t.Error("expected MSGID 'auth.failure' for deny decision")
	}
}

func TestSyslogWriter_BypassEvent(t *testing.T) {
	t.Log("Testing that force bypass events produce attestation.bypass with WARNING severity")

	socketPath := testSocketPath("bypass")
	t.Cleanup(func() { os.Remove(socketPath) })

	addr := net.UnixAddr{Name: socketPath, Net: "unixgram"}
	conn, err := net.ListenUnixgram("unixgram", &addr)
	if err != nil {
		t.Fatalf("failed to create mock syslog listener: %v", err)
	}
	defer conn.Close()

	writer, err := NewSyslogWriter(SyslogConfig{
		SocketPath: socketPath,
		Hostname:   "test.local",
		AppName:    "nexus",
	})
	if err != nil {
		t.Fatalf("NewSyslogWriter failed: %v", err)
	}
	defer writer.Close()

	entry := authz.AuthzAuditEntry{
		Timestamp:         time.Now(),
		Principal:         "adm_root",
		Action:            "credential:push",
		Resource:          "/api/v1/push",
		Decision:          "allow",
		Reason:            "force bypass active",
		ForceBypass:       true,
		BypassReason:      "emergency maintenance",
		AttestationStatus: "stale",
	}

	t.Log("Writing bypass event")
	if err := writer.LogDecision(context.Background(), entry); err != nil {
		t.Fatalf("LogDecision failed: %v", err)
	}

	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read from mock socket: %v", err)
	}

	got := string(buf[:n])
	t.Logf("Received message: %s", got)

	if !strings.HasPrefix(got, "<132>1") {
		t.Errorf("expected priority <132>1 (Local0+WARNING), got prefix: %s", got[:10])
	}
	if !strings.Contains(got, "attestation.bypass") {
		t.Error("expected MSGID 'attestation.bypass' for force bypass")
	}
	if !strings.Contains(got, `bypass_reason="emergency maintenance"`) {
		t.Error("bypass_reason SD param not found")
	}
	if !strings.Contains(got, `attestation_status="stale"`) {
		t.Error("attestation_status SD param not found")
	}
}

func TestSyslogWriter_ConcurrentWrites(t *testing.T) {
	t.Log("Testing that concurrent LogDecision calls serialize correctly via mutex")

	socketPath := testSocketPath("concurrent")
	t.Cleanup(func() { os.Remove(socketPath) })

	addr := net.UnixAddr{Name: socketPath, Net: "unixgram"}
	conn, err := net.ListenUnixgram("unixgram", &addr)
	if err != nil {
		t.Fatalf("failed to create mock syslog listener: %v", err)
	}
	defer conn.Close()

	writer, err := NewSyslogWriter(SyslogConfig{
		SocketPath: socketPath,
		Hostname:   "test.local",
		AppName:    "nexus",
	})
	if err != nil {
		t.Fatalf("NewSyslogWriter failed: %v", err)
	}
	defer writer.Close()

	const numWriters = 10
	var wg sync.WaitGroup
	wg.Add(numWriters)

	t.Logf("Launching %d concurrent writers", numWriters)
	for i := 0; i < numWriters; i++ {
		go func(idx int) {
			defer wg.Done()
			entry := authz.AuthzAuditEntry{
				Timestamp: time.Now(),
				Principal: fmt.Sprintf("km_user%d", idx),
				Action:    "credential:push",
				Resource:  "/api/v1/push",
				Decision:  "allow",
				Reason:    fmt.Sprintf("concurrent write %d", idx),
			}
			writer.LogDecision(context.Background(), entry)
		}(i)
	}

	wg.Wait()

	// Read all messages from socket
	t.Log("Reading messages from socket")
	received := 0
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		msg := string(buf[:n])
		if strings.HasPrefix(msg, "<134>1") {
			received++
		}
	}

	t.Logf("Received %d/%d messages", received, numWriters)
	if received != numWriters {
		t.Errorf("expected %d messages, got %d", numWriters, received)
	}
}

func TestSyslogWriter_UnavailableSocket(t *testing.T) {
	t.Log("Testing graceful handling when syslog socket doesn't exist")

	_, err := NewSyslogWriter(SyslogConfig{
		SocketPath: "/tmp/nonexistent_syslog_socket_for_test",
	})

	if err == nil {
		t.Fatal("expected error when socket doesn't exist, got nil")
	}

	t.Logf("Got expected error: %v", err)

	if !strings.Contains(err.Error(), "syslog connect") {
		t.Errorf("error should contain 'syslog connect', got: %v", err)
	}
}

func TestSyslogWriter_StreamFallback(t *testing.T) {
	t.Log("Testing fallback from unixgram to unix stream socket")

	socketPath := testSocketPath("stream")
	t.Cleanup(func() { os.Remove(socketPath) })

	// Create a stream (not datagram) listener to test fallback
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create stream listener: %v", err)
	}
	defer listener.Close()

	// Accept connections in background
	connCh := make(chan net.Conn, 1)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			connCh <- c
		}
	}()

	writer, err := NewSyslogWriter(SyslogConfig{
		SocketPath: socketPath,
		Hostname:   "test.local",
		AppName:    "nexus",
	})
	if err != nil {
		t.Fatalf("NewSyslogWriter failed with stream socket: %v", err)
	}
	defer writer.Close()

	t.Log("Successfully connected via stream socket fallback")

	// Write an event
	entry := authz.AuthzAuditEntry{
		Timestamp: time.Now(),
		Principal: "km_test",
		Action:    "credential:push",
		Resource:  "/api/v1/push",
		Decision:  "allow",
		Reason:    "stream fallback test",
	}

	if err := writer.LogDecision(context.Background(), entry); err != nil {
		t.Fatalf("LogDecision failed on stream socket: %v", err)
	}

	// Read from the accepted connection
	select {
	case serverConn := <-connCh:
		defer serverConn.Close()
		buf := make([]byte, 4096)
		serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := serverConn.Read(buf)
		if err != nil {
			t.Fatalf("failed to read from stream connection: %v", err)
		}
		got := string(buf[:n])
		t.Logf("Received via stream: %s", got)
		if !strings.Contains(got, "auth.success") {
			t.Error("expected auth.success in stream message")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for stream connection")
	}
}

func TestSyslogWriter_Reconnect(t *testing.T) {
	t.Log("Testing that SyslogAuditLogger reconnects after socket failure")

	socketPath := testSocketPath("reconnect")
	t.Cleanup(func() { os.Remove(socketPath) })

	// Phase 1: Start listener, create writer, verify initial write works.
	t.Log("Phase 1: initial write succeeds")
	addr := net.UnixAddr{Name: socketPath, Net: "unixgram"}
	listener1, err := net.ListenUnixgram("unixgram", &addr)
	if err != nil {
		t.Fatalf("failed to create mock syslog listener: %v", err)
	}

	writer, err := NewSyslogWriter(SyslogConfig{
		SocketPath: socketPath,
		Hostname:   "test.local",
		AppName:    "nexus",
	})
	if err != nil {
		listener1.Close()
		t.Fatalf("NewSyslogWriter failed: %v", err)
	}
	defer writer.Close()

	entry := authz.AuthzAuditEntry{
		Timestamp: time.Now(),
		Principal: "km_reconntest",
		Action:    "credential:push",
		Resource:  "/api/v1/push",
		Decision:  "allow",
		Reason:    "phase1",
	}

	if err := writer.LogDecision(context.Background(), entry); err != nil {
		t.Fatalf("Phase 1 write failed: %v", err)
	}

	buf := make([]byte, 4096)
	listener1.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := listener1.Read(buf)
	if err != nil {
		t.Fatalf("Phase 1 read failed: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "phase1") {
		t.Fatalf("Phase 1 message mismatch: %s", buf[:n])
	}
	t.Log("Phase 1 passed: initial write delivered")

	// Phase 2: Kill listener, write should fail (no listener to reconnect to).
	t.Log("Phase 2: write fails after socket death, reconnect fails")
	listener1.Close()
	os.Remove(socketPath)

	entry.Reason = "phase2"
	err = writer.LogDecision(context.Background(), entry)
	if err == nil {
		t.Fatal("Phase 2: expected error after socket death, got nil")
	}
	t.Logf("Phase 2 got expected error: %v", err)

	// Phase 3: Restart listener on same path, next write should reconnect.
	t.Log("Phase 3: write succeeds after listener restart (reconnection)")
	// Wait for backoff to expire (initial backoff is 100ms).
	time.Sleep(150 * time.Millisecond)

	listener2, err := net.ListenUnixgram("unixgram", &addr)
	if err != nil {
		t.Fatalf("failed to create second listener: %v", err)
	}
	defer listener2.Close()

	entry.Reason = "phase3"
	if err := writer.LogDecision(context.Background(), entry); err != nil {
		t.Fatalf("Phase 3 write failed (reconnect should have succeeded): %v", err)
	}

	listener2.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = listener2.Read(buf)
	if err != nil {
		t.Fatalf("Phase 3 read failed: %v", err)
	}
	got := string(buf[:n])
	if !strings.Contains(got, "phase3") {
		t.Fatalf("Phase 3 message mismatch: %s", got)
	}
	t.Log("Phase 3 passed: reconnection successful, message delivered")
}

func TestSyslogWriter_ReconnectBackoff(t *testing.T) {
	t.Log("Testing that repeated reconnect failures increase backoff (no tight loop)")

	socketPath := testSocketPath("backoff")
	t.Cleanup(func() { os.Remove(socketPath) })

	// Create listener just to bootstrap the writer, then kill it.
	addr := net.UnixAddr{Name: socketPath, Net: "unixgram"}
	listener, err := net.ListenUnixgram("unixgram", &addr)
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	writer, err := NewSyslogWriter(SyslogConfig{
		SocketPath: socketPath,
		Hostname:   "test.local",
		AppName:    "nexus",
	})
	if err != nil {
		listener.Close()
		t.Fatalf("NewSyslogWriter failed: %v", err)
	}
	defer writer.Close()

	listener.Close()
	os.Remove(socketPath)

	entry := authz.AuthzAuditEntry{
		Timestamp: time.Now(),
		Principal: "km_backoff",
		Action:    "credential:push",
		Resource:  "/api/v1/push",
		Decision:  "allow",
		Reason:    "backoff test",
	}

	// First failure: triggers reconnect attempt, sets initial backoff.
	t.Log("First write: triggers reconnect, sets backoff")
	err1 := writer.LogDecision(context.Background(), entry)
	if err1 == nil {
		t.Fatal("expected error on first write after socket death")
	}
	t.Logf("First error: %v", err1)

	// Second failure immediately: should hit backoff gate (no reconnect attempt).
	t.Log("Second write immediately: should be gated by backoff")
	err2 := writer.LogDecision(context.Background(), entry)
	if err2 == nil {
		t.Fatal("expected error on second write (backoff should block reconnect)")
	}
	if !strings.Contains(err2.Error(), "backoff") {
		t.Errorf("expected backoff error, got: %v", err2)
	}
	t.Logf("Second error (backoff gated): %v", err2)
}

func TestSyslogWriter_NilReceiverSafety(t *testing.T) {
	t.Log("Verifying nil *SyslogAuditLogger does not panic on Emit, LogDecision, or Close")

	var w *SyslogAuditLogger

	t.Log("Calling Emit on nil receiver")
	if err := w.Emit(Event{Type: EventAuthSuccess}); err != nil {
		t.Errorf("Emit on nil receiver returned error: %v", err)
	}

	t.Log("Calling LogDecision on nil receiver")
	if err := w.LogDecision(context.Background(), authz.AuthzAuditEntry{
		Principal: "km_test",
		Action:    "credential:push",
		Decision:  "allow",
	}); err != nil {
		t.Errorf("LogDecision on nil receiver returned error: %v", err)
	}

	t.Log("Calling Close on nil receiver")
	if err := w.Close(); err != nil {
		t.Errorf("Close on nil receiver returned error: %v", err)
	}
}

func TestDeriveEventType(t *testing.T) {
	t.Log("Testing event type derivation from AuthzAuditEntry fields")

	tests := []struct {
		name      string
		entry     authz.AuthzAuditEntry
		wantEvent string
		wantSev   Severity
	}{
		{
			name:      "allow -> auth.success",
			entry:     authz.AuthzAuditEntry{Decision: "allow"},
			wantEvent: "auth.success",
			wantSev:   SeverityInfo,
		},
		{
			name:      "deny -> auth.failure",
			entry:     authz.AuthzAuditEntry{Decision: "deny"},
			wantEvent: "auth.failure",
			wantSev:   SeverityWarning,
		},
		{
			name:      "bypass overrides decision",
			entry:     authz.AuthzAuditEntry{Decision: "allow", ForceBypass: true},
			wantEvent: "attestation.bypass",
			wantSev:   SeverityWarning,
		},
		{
			name:      "unknown decision defaults to auth.unknown",
			entry:     authz.AuthzAuditEntry{Decision: ""},
			wantEvent: "auth.unknown",
			wantSev:   SeverityInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEvent, gotSev := deriveEventType(tt.entry)
			if gotEvent != tt.wantEvent {
				t.Errorf("event type: got %q, want %q", gotEvent, tt.wantEvent)
			}
			if gotSev != tt.wantSev {
				t.Errorf("severity: got %d, want %d", gotSev, tt.wantSev)
			}
		})
	}
}
