//go:build benchmark

package benchmark

import (
	"encoding/json"
	"testing"

	"github.com/gobeyondidentity/cobalt/pkg/transport"
)

// BenchmarkTransportMessageMarshal measures client-side message serialization.
func BenchmarkTransportMessageMarshal(b *testing.B) {
	msg := &transport.Message{
		Type:    transport.MessagePostureReport,
		Payload: json.RawMessage(`{"score":95,"checks":["firewall","disk","software"],"timestamp":"2026-01-20T12:00:00Z"}`),
		ID:      "benchmark-nonce-12345",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkTransportMessageUnmarshal measures message deserialization.
func BenchmarkTransportMessageUnmarshal(b *testing.B) {
	data := []byte(`{"type":"POSTURE_REPORT","payload":{"score":95,"checks":["firewall","disk","software"],"timestamp":"2026-01-20T12:00:00Z"},"nonce":"benchmark-nonce-12345"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var msg transport.Message
		if err := json.Unmarshal(data, &msg); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkServerMessageMarshal measures server-side message serialization.
func BenchmarkServerMessageMarshal(b *testing.B) {
	msg := &transport.Message{
		Type:    transport.MessageEnrollResponse,
		Payload: json.RawMessage(`{"host_id":"h-12345","status":"enrolled","assigned_policies":["base","high-security"]}`),
		ID:      "benchmark-nonce-server",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}
