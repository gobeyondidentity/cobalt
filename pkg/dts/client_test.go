package dts

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gobeyondidentity/cobalt/internal/testutil/mockhttp"
)

func TestParsePrometheusText(t *testing.T) {
	input := `
# HELP node_cpu_percent CPU usage percentage
# TYPE node_cpu_percent gauge
node_cpu_percent 25.5
node_memory_used_bytes 8589934592
node_memory_total_bytes 34359738368
node_load1 1.5
node_network_receive_packets_total{device="p0"} 1234567
node_network_transmit_packets_total{device="p0"} 7654321
dts_ovs_hits{bridge="ovs-br0"} 999999
`

	metrics := parsePrometheusText(input)

	tests := []struct {
		key      string
		expected string
	}{
		{"node_cpu_percent", "25.5"},
		{"node_memory_used_bytes", "8589934592"},
		{"node_memory_total_bytes", "34359738368"},
		{"node_load1", "1.5"},
		{`node_network_receive_packets_total{device="p0"}`, "1234567"},
		{`dts_ovs_hits{bridge="ovs-br0"}`, "999999"},
	}

	for _, tt := range tests {
		got, ok := metrics[tt.key]
		if !ok {
			t.Errorf("missing key %q", tt.key)
			continue
		}
		if got != tt.expected {
			t.Errorf("key %q: got %q, want %q", tt.key, got, tt.expected)
		}
	}
}

func TestExtractLabel(t *testing.T) {
	tests := []struct {
		metric   string
		labels   []string
		expected string
	}{
		{`node_network_receive_packets_total{device="p0"}`, []string{"device"}, "p0"},
		{`dts_ethtool_rx_bytes{interface="enp3s0f0"}`, []string{"interface"}, "enp3s0f0"},
		{`dts_ovs_hits{bridge="ovs-br0",port="1"}`, []string{"bridge"}, "ovs-br0"},
		{`node_cpu_percent`, []string{"device"}, ""},
		{`foo{bar="baz"}`, []string{"missing"}, ""},
	}

	for _, tt := range tests {
		got := extractLabel(tt.metric, tt.labels...)
		if got != tt.expected {
			t.Errorf("extractLabel(%q, %v): got %q, want %q", tt.metric, tt.labels, got, tt.expected)
		}
	}
}

func TestClientPing(t *testing.T) {
	// Create test server using mockhttp builder
	url, close := mockhttp.New().
		Text("/metrics", "# OK\n").
		BuildURL()
	defer close()

	// Use withSkipValidation since httptest servers use 127.0.0.1
	client, err := NewClient(url, withSkipValidation())
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	err = client.Ping(context.Background())
	if err != nil {
		t.Errorf("Ping failed: %v", err)
	}
}

func TestClientPingFailure(t *testing.T) {
	// Create a test server that returns 500 to test connection failure handling
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Close connection immediately to simulate unavailable service
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Use withSkipValidation since httptest servers use 127.0.0.1
	client, err := NewClient(server.URL, withSkipValidation())
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = client.Ping(ctx)
	if err != ErrNotAvailable {
		t.Errorf("expected ErrNotAvailable, got %v", err)
	}
}

func TestNewClient_BlocksLoopback(t *testing.T) {
	// NewClient with strict validation should block loopback addresses
	_, err := NewClient("http://localhost:9100")
	if err == nil {
		t.Error("expected error for localhost, got nil")
	}
	_, err = NewClient("127.0.0.1:9100")
	if err == nil {
		t.Error("expected error for 127.0.0.1, got nil")
	}
}

func TestNewClient_BlocksPrivateRanges(t *testing.T) {
	// NewClient with strict validation should block private ranges
	_, err := NewClient("192.168.1.1:9100")
	if err == nil {
		t.Error("expected error for 192.168.1.1, got nil")
	}
	_, err = NewClient("10.0.0.1:9100")
	if err == nil {
		t.Error("expected error for 10.0.0.1, got nil")
	}
}

func TestClientGetMetrics(t *testing.T) {
	prometheusData := `
# HELP node_cpu_percent CPU usage
node_cpu_percent 45.2
node_memory_used_bytes 17179869184
node_memory_total_bytes 34359738368
node_load1 2.5
node_load5 1.8
node_load15 1.2
dts_diagnostic_temperature 52.0
dts_diagnostic_power_watts 75.5
node_network_receive_packets_total{device="p0"} 1000000
node_network_transmit_packets_total{device="p0"} 500000
node_network_receive_bytes_total{device="p0"} 1500000000
node_network_transmit_bytes_total{device="p0"} 750000000
dts_ovs_hits{bridge="ovs-br0"} 999999
dts_ovs_misses{bridge="ovs-br0"} 1000
`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(prometheusData))
	}))
	defer server.Close()

	// Use withSkipValidation since httptest servers use 127.0.0.1
	client, err := NewClient(server.URL, withSkipValidation())
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	metrics, err := client.GetMetrics(context.Background())
	if err != nil {
		t.Fatalf("GetMetrics failed: %v", err)
	}

	// Check system metrics
	if metrics.System == nil {
		t.Fatal("System metrics nil")
	}
	if metrics.System.CPUPercent != 45.2 {
		t.Errorf("CPUPercent: got %v, want 45.2", metrics.System.CPUPercent)
	}
	if metrics.System.MemoryUsedBytes != 17179869184 {
		t.Errorf("MemoryUsedBytes: got %v, want 17179869184", metrics.System.MemoryUsedBytes)
	}
	if metrics.System.LoadAvg1m != 2.5 {
		t.Errorf("LoadAvg1m: got %v, want 2.5", metrics.System.LoadAvg1m)
	}

	// Check hardware metrics
	if metrics.Hardware == nil {
		t.Fatal("Hardware metrics nil")
	}
	if metrics.Hardware.TemperatureCelsius != 52.0 {
		t.Errorf("Temperature: got %v, want 52.0", metrics.Hardware.TemperatureCelsius)
	}
	if metrics.Hardware.PowerWatts != 75.5 {
		t.Errorf("PowerWatts: got %v, want 75.5", metrics.Hardware.PowerWatts)
	}

	// Check network metrics
	if metrics.Network == nil {
		t.Fatal("Network metrics nil")
	}
	p0, ok := metrics.Network.Interfaces["p0"]
	if !ok {
		t.Fatal("missing interface p0")
	}
	if p0.RXPackets != 1000000 {
		t.Errorf("p0 RXPackets: got %v, want 1000000", p0.RXPackets)
	}
	if p0.TXBytes != 750000000 {
		t.Errorf("p0 TXBytes: got %v, want 750000000", p0.TXBytes)
	}

	// Check OVS metrics
	if metrics.OVS == nil {
		t.Fatal("OVS metrics nil")
	}
	br0, ok := metrics.OVS.Bridges["ovs-br0"]
	if !ok {
		t.Fatal("missing bridge ovs-br0")
	}
	if br0.FlowHits != 999999 {
		t.Errorf("ovs-br0 FlowHits: got %v, want 999999", br0.FlowHits)
	}
}

func TestWithTimeout(t *testing.T) {
	// Create a test server using mockhttp builder
	url, close := mockhttp.New().
		Status("/", http.StatusOK).
		BuildURL()
	defer close()

	// Use withSkipValidation since httptest servers use 127.0.0.1
	client, err := NewClient(url, WithTimeout(5*time.Second), withSkipValidation())
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	if client.httpClient.Timeout != 5*time.Second {
		t.Errorf("timeout not set correctly")
	}
}
