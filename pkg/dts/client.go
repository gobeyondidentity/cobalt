// Package dts provides a client for querying DOCA Telemetry Service (DTS).
// DTS aggregates metrics from multiple providers on BlueField DPUs.
package dts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/netutil"
)

var (
	// ErrNotAvailable indicates DTS is not running or reachable
	ErrNotAvailable = errors.New("dts: service not available")

	// ErrProviderDisabled indicates the requested provider is not enabled
	ErrProviderDisabled = errors.New("dts: provider not enabled")
)

// Client provides access to DTS metrics
type Client struct {
	baseURL        string
	httpClient     *http.Client
	skipValidation bool // for testing only
}

// Option configures the client
type Option func(*Client)

// WithTimeout sets the HTTP client timeout
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.httpClient.Timeout = d
	}
}

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		c.httpClient = hc
	}
}

// withSkipValidation skips SSRF validation (for testing only).
// This is unexported to prevent misuse in production code.
func withSkipValidation() Option {
	return func(c *Client) {
		c.skipValidation = true
	}
}

// NewClient creates a DTS client with SSRF protection.
// endpoint should be host:port (e.g., "192.168.1.204:9100") or full URL.
// Returns an error if the endpoint resolves to a blocked address range
// (loopback, link-local, or private ranges).
func NewClient(endpoint string, opts ...Option) (*Client, error) {
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = "http://" + endpoint
	}

	c := &Client{
		baseURL: endpoint,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	// Apply options first so we can check skipValidation
	for _, opt := range opts {
		opt(c)
	}

	// Validate endpoint for SSRF protection (unless explicitly skipped for testing)
	if !c.skipValidation {
		if err := netutil.ValidateEndpointStrict(endpoint); err != nil {
			return nil, fmt.Errorf("dts: invalid endpoint: %w", err)
		}
	}

	return c, nil
}

// Ping checks if DTS is reachable
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/metrics", nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ErrNotAvailable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("dts: unexpected status %d", resp.StatusCode)
	}

	return nil
}

// Metrics contains all telemetry data from DTS
type Metrics struct {
	Timestamp time.Time         `json:"timestamp"`
	Hostname  string            `json:"hostname"`
	System    *SystemMetrics    `json:"system,omitempty"`
	Network   *NetworkMetrics   `json:"network,omitempty"`
	Hardware  *HardwareMetrics  `json:"hardware,omitempty"`
	OVS       *OVSMetrics       `json:"ovs,omitempty"`
	ARM       *ARMMetrics       `json:"arm,omitempty"`
	Raw       map[string]string `json:"raw,omitempty"`
}

// SystemMetrics from sysfs provider
type SystemMetrics struct {
	CPUPercent       float64 `json:"cpu_percent"`
	MemoryUsedBytes  uint64  `json:"memory_used_bytes"`
	MemoryTotalBytes uint64  `json:"memory_total_bytes"`
	MemoryPercent    float64 `json:"memory_percent"`
	DiskUsedBytes    uint64  `json:"disk_used_bytes"`
	DiskTotalBytes   uint64  `json:"disk_total_bytes"`
	DiskPercent      float64 `json:"disk_percent"`
	LoadAvg1m        float64 `json:"load_avg_1m"`
	LoadAvg5m        float64 `json:"load_avg_5m"`
	LoadAvg15m       float64 `json:"load_avg_15m"`
	UptimeSeconds    uint64  `json:"uptime_seconds"`
}

// NetworkMetrics from ethtool provider
type NetworkMetrics struct {
	Interfaces map[string]*InterfaceStats `json:"interfaces"`
}

// InterfaceStats for a single network interface
type InterfaceStats struct {
	LinkUp       bool   `json:"link_up"`
	SpeedMbps    uint64 `json:"speed_mbps"`
	RXPackets    uint64 `json:"rx_packets"`
	TXPackets    uint64 `json:"tx_packets"`
	RXBytes      uint64 `json:"rx_bytes"`
	TXBytes      uint64 `json:"tx_bytes"`
	RXErrors     uint64 `json:"rx_errors"`
	TXErrors     uint64 `json:"tx_errors"`
	RXDropped    uint64 `json:"rx_dropped"`
	TXDropped    uint64 `json:"tx_dropped"`
	Multicast    uint64 `json:"multicast"`
	Collisions   uint64 `json:"collisions"`
	RXCRCErrors  uint64 `json:"rx_crc_errors"`
	RXOverErrors uint64 `json:"rx_over_errors"`
}

// HardwareMetrics from diagnostic_data provider
type HardwareMetrics struct {
	TemperatureCelsius float64 `json:"temperature_celsius"`
	VoltageMV          uint64  `json:"voltage_mv"`
	PowerWatts         float64 `json:"power_watts"`
	FanRPM             uint64  `json:"fan_rpm,omitempty"`
}

// OVSMetrics from ovs provider
type OVSMetrics struct {
	Bridges map[string]*BridgeStats `json:"bridges"`
}

// BridgeStats for an OVS bridge
type BridgeStats struct {
	FlowHits    uint64 `json:"flow_hits"`
	FlowMisses  uint64 `json:"flow_misses"`
	FlowCount   uint64 `json:"flow_count"`
	PacketsIn   uint64 `json:"packets_in"`
	PacketsOut  uint64 `json:"packets_out"`
	BytesIn     uint64 `json:"bytes_in"`
	BytesOut    uint64 `json:"bytes_out"`
	Errors      uint64 `json:"errors"`
	TableLookup uint64 `json:"table_lookup"`
	TableMatch  uint64 `json:"table_match"`
}

// ARMMetrics from bfperf provider
type ARMMetrics struct {
	Cores []CoreStats `json:"cores"`
}

// CoreStats for ARM core performance counters
type CoreStats struct {
	CoreID           int     `json:"core_id"`
	Cycles           uint64  `json:"cycles"`
	Instructions     uint64  `json:"instructions"`
	IPC              float64 `json:"ipc"`
	CacheHits        uint64  `json:"cache_hits"`
	CacheMisses      uint64  `json:"cache_misses"`
	CacheHitRate     float64 `json:"cache_hit_rate"`
	BranchHits       uint64  `json:"branch_hits"`
	BranchMisses     uint64  `json:"branch_misses"`
	BranchPrediction float64 `json:"branch_prediction_rate"`
}

// GetMetrics fetches all available metrics from DTS
func (c *Client) GetMetrics(ctx context.Context) (*Metrics, error) {
	raw, err := c.getRawPrometheus(ctx)
	if err != nil {
		return nil, err
	}

	return c.parsePrometheus(raw)
}

// GetSystemMetrics fetches only system metrics (sysfs provider)
func (c *Client) GetSystemMetrics(ctx context.Context) (*SystemMetrics, error) {
	m, err := c.GetMetrics(ctx)
	if err != nil {
		return nil, err
	}
	if m.System == nil {
		return nil, ErrProviderDisabled
	}
	return m.System, nil
}

// GetNetworkMetrics fetches only network metrics (ethtool provider)
func (c *Client) GetNetworkMetrics(ctx context.Context) (*NetworkMetrics, error) {
	m, err := c.GetMetrics(ctx)
	if err != nil {
		return nil, err
	}
	if m.Network == nil {
		return nil, ErrProviderDisabled
	}
	return m.Network, nil
}

// GetHardwareMetrics fetches only hardware metrics (diagnostic_data provider)
func (c *Client) GetHardwareMetrics(ctx context.Context) (*HardwareMetrics, error) {
	m, err := c.GetMetrics(ctx)
	if err != nil {
		return nil, err
	}
	if m.Hardware == nil {
		return nil, ErrProviderDisabled
	}
	return m.Hardware, nil
}

// GetOVSMetrics fetches only OVS metrics
func (c *Client) GetOVSMetrics(ctx context.Context) (*OVSMetrics, error) {
	m, err := c.GetMetrics(ctx)
	if err != nil {
		return nil, err
	}
	if m.OVS == nil {
		return nil, ErrProviderDisabled
	}
	return m.OVS, nil
}

// GetARMMetrics fetches only ARM performance counters (bfperf provider)
func (c *Client) GetARMMetrics(ctx context.Context) (*ARMMetrics, error) {
	m, err := c.GetMetrics(ctx)
	if err != nil {
		return nil, err
	}
	if m.ARM == nil {
		return nil, ErrProviderDisabled
	}
	return m.ARM, nil
}

// GetJSON fetches metrics in JSON format (if supported by DTS)
func (c *Client) GetJSON(ctx context.Context) (*Metrics, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/json/metrics", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, ErrNotAvailable
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// JSON endpoint not available, fall back to Prometheus
		return c.GetMetrics(ctx)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dts: unexpected status %d", resp.StatusCode)
	}

	var m Metrics
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("dts: failed to decode JSON: %w", err)
	}

	return &m, nil
}

// getRawPrometheus fetches raw Prometheus metrics text
func (c *Client) getRawPrometheus(ctx context.Context) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/metrics", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, ErrNotAvailable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dts: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("dts: failed to read response: %w", err)
	}

	return parsePrometheusText(string(body)), nil
}

// parsePrometheusText parses Prometheus exposition format into a map
func parsePrometheusText(text string) map[string]string {
	metrics := make(map[string]string)

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse: metric_name{labels} value
		// or:    metric_name value
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}

		name := parts[0]
		value := strings.TrimSpace(parts[1])
		metrics[name] = value
	}

	return metrics
}

// parsePrometheus converts raw Prometheus metrics into structured Metrics
func (c *Client) parsePrometheus(raw map[string]string) (*Metrics, error) {
	m := &Metrics{
		Timestamp: time.Now(),
		Raw:       raw,
	}

	// Parse system metrics (sysfs provider)
	if hasPrefix(raw, "node_") || hasPrefix(raw, "dts_sysfs_") {
		m.System = &SystemMetrics{}
		m.System.CPUPercent = parseFloat(raw, "node_cpu_percent", "dts_sysfs_cpu_percent")
		m.System.MemoryUsedBytes = parseUint(raw, "node_memory_used_bytes", "dts_sysfs_memory_used")
		m.System.MemoryTotalBytes = parseUint(raw, "node_memory_total_bytes", "dts_sysfs_memory_total")
		if m.System.MemoryTotalBytes > 0 {
			m.System.MemoryPercent = float64(m.System.MemoryUsedBytes) / float64(m.System.MemoryTotalBytes) * 100
		}
		m.System.LoadAvg1m = parseFloat(raw, "node_load1", "dts_sysfs_load1")
		m.System.LoadAvg5m = parseFloat(raw, "node_load5", "dts_sysfs_load5")
		m.System.LoadAvg15m = parseFloat(raw, "node_load15", "dts_sysfs_load15")
		m.System.UptimeSeconds = parseUint(raw, "node_boot_time_seconds", "dts_sysfs_uptime")
	}

	// Parse hardware metrics (diagnostic_data provider)
	if hasPrefix(raw, "dts_diagnostic_") || hasPrefix(raw, "node_hwmon_") {
		m.Hardware = &HardwareMetrics{}
		m.Hardware.TemperatureCelsius = parseFloat(raw, "dts_diagnostic_temperature", "node_hwmon_temp_celsius")
		m.Hardware.VoltageMV = parseUint(raw, "dts_diagnostic_voltage_mv", "node_hwmon_in_volts")
		m.Hardware.PowerWatts = parseFloat(raw, "dts_diagnostic_power_watts", "node_hwmon_power_watts")
	}

	// Parse network metrics (ethtool provider)
	m.Network = c.parseNetworkMetrics(raw)

	// Parse OVS metrics
	m.OVS = c.parseOVSMetrics(raw)

	return m, nil
}

// parseNetworkMetrics extracts network interface stats from Prometheus metrics
func (c *Client) parseNetworkMetrics(raw map[string]string) *NetworkMetrics {
	interfaces := make(map[string]*InterfaceStats)

	for key, value := range raw {
		// Look for metrics like: node_network_receive_packets_total{device="p0"}
		// or: dts_ethtool_rx_packets{interface="p0"}
		if !strings.Contains(key, "network") && !strings.Contains(key, "ethtool") {
			continue
		}

		iface := extractLabel(key, "device", "interface")
		if iface == "" {
			continue
		}

		if _, exists := interfaces[iface]; !exists {
			interfaces[iface] = &InterfaceStats{}
		}

		stats := interfaces[iface]
		v, _ := strconv.ParseUint(value, 10, 64)

		switch {
		case strings.Contains(key, "receive_packets") || strings.Contains(key, "rx_packets"):
			stats.RXPackets = v
		case strings.Contains(key, "transmit_packets") || strings.Contains(key, "tx_packets"):
			stats.TXPackets = v
		case strings.Contains(key, "receive_bytes") || strings.Contains(key, "rx_bytes"):
			stats.RXBytes = v
		case strings.Contains(key, "transmit_bytes") || strings.Contains(key, "tx_bytes"):
			stats.TXBytes = v
		case strings.Contains(key, "receive_errs") || strings.Contains(key, "rx_errors"):
			stats.RXErrors = v
		case strings.Contains(key, "transmit_errs") || strings.Contains(key, "tx_errors"):
			stats.TXErrors = v
		case strings.Contains(key, "receive_drop") || strings.Contains(key, "rx_dropped"):
			stats.RXDropped = v
		case strings.Contains(key, "transmit_drop") || strings.Contains(key, "tx_dropped"):
			stats.TXDropped = v
		case strings.Contains(key, "speed"):
			stats.SpeedMbps = v
		}
	}

	if len(interfaces) == 0 {
		return nil
	}

	return &NetworkMetrics{Interfaces: interfaces}
}

// parseOVSMetrics extracts OVS bridge stats from Prometheus metrics
func (c *Client) parseOVSMetrics(raw map[string]string) *OVSMetrics {
	bridges := make(map[string]*BridgeStats)

	for key, value := range raw {
		if !strings.Contains(key, "ovs") {
			continue
		}

		bridge := extractLabel(key, "bridge", "datapath")
		if bridge == "" {
			continue
		}

		if _, exists := bridges[bridge]; !exists {
			bridges[bridge] = &BridgeStats{}
		}

		stats := bridges[bridge]
		v, _ := strconv.ParseUint(value, 10, 64)

		switch {
		case strings.Contains(key, "hit"):
			stats.FlowHits = v
		case strings.Contains(key, "miss"):
			stats.FlowMisses = v
		case strings.Contains(key, "flow_count") || strings.Contains(key, "flows"):
			stats.FlowCount = v
		case strings.Contains(key, "lookup"):
			stats.TableLookup = v
		case strings.Contains(key, "match"):
			stats.TableMatch = v
		}
	}

	if len(bridges) == 0 {
		return nil
	}

	return &OVSMetrics{Bridges: bridges}
}

// hasPrefix checks if any key in the map starts with any of the prefixes
func hasPrefix(m map[string]string, prefixes ...string) bool {
	for key := range m {
		for _, prefix := range prefixes {
			if strings.HasPrefix(key, prefix) {
				return true
			}
		}
	}
	return false
}

// parseFloat tries multiple metric names and returns the first found value
func parseFloat(m map[string]string, names ...string) float64 {
	for _, name := range names {
		if v, ok := m[name]; ok {
			f, _ := strconv.ParseFloat(v, 64)
			return f
		}
	}
	return 0
}

// parseUint tries multiple metric names and returns the first found value
func parseUint(m map[string]string, names ...string) uint64 {
	for _, name := range names {
		if v, ok := m[name]; ok {
			u, _ := strconv.ParseUint(v, 10, 64)
			return u
		}
	}
	return 0
}

// extractLabel extracts a label value from a Prometheus metric name
// e.g., extractLabel("foo{bar=\"baz\"}", "bar") returns "baz"
func extractLabel(metric string, labelNames ...string) string {
	start := strings.Index(metric, "{")
	end := strings.Index(metric, "}")
	if start == -1 || end == -1 || end <= start {
		return ""
	}

	labels := metric[start+1 : end]
	for _, part := range strings.Split(labels, ",") {
		for _, name := range labelNames {
			prefix := name + "=\""
			if strings.HasPrefix(part, prefix) {
				value := strings.TrimPrefix(part, prefix)
				value = strings.TrimSuffix(value, "\"")
				return value
			}
		}
	}

	return ""
}
