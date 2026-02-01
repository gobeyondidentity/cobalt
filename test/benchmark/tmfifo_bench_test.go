//go:build benchmark

package benchmark

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nmelo/secure-infra/internal/aegis/tmfifo"
)

// BenchmarkTMFIFOGenerateNonce measures nonce generation performance.
func BenchmarkTMFIFOGenerateNonce(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = tmfifo.GenerateNonce()
	}
}

// BenchmarkTMFIFONonceRecording measures nonce recording performance.
func BenchmarkTMFIFONonceRecording(b *testing.B) {
	listener := tmfifo.NewListener("/dev/null", nil)
	nonces := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		nonces[i] = tmfifo.GenerateNonce()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		listener.RecordNonce(nonces[i])
	}
}

// BenchmarkTMFIFOMessageMarshal measures message marshaling performance.
func BenchmarkTMFIFOMessageMarshal(b *testing.B) {
	payload := tmfifo.EnrollRequestPayload{
		Hostname: "test-host",
		Posture:  json.RawMessage(`{"secure_boot":true,"disk_encryption":"luks"}`),
	}
	payloadBytes, _ := json.Marshal(payload)
	msg := tmfifo.Message{
		Version: tmfifo.ProtocolVersion,
		Type:    tmfifo.TypeEnrollRequest,
		ID:      "test-nonce-12345",
		TS:      time.Now().UnixMilli(),
		Payload: payloadBytes,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(msg)
	}
}
