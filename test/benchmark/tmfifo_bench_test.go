//go:build benchmark

package benchmark

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/gobeyondidentity/secure-infra/internal/aegis/tmfifo"
)

// BenchmarkTMFIFOGenerateNonce and BenchmarkTMFIFONonceRecording disabled
// - generateNonce and recordNonce are unexported
// TODO: Export these functions or move benchmarks to tmfifo package

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
