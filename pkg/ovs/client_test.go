package ovs

import (
	"testing"
)

func TestParseFlows(t *testing.T) {
	// Real output from bluefield3
	input := `NXST_FLOW reply (xid=0x4):
 cookie=0x0, duration=588418.364s, table=0, n_packets=734592734, n_bytes=4075072624557, idle_age=16, hard_age=65534, priority=0 actions=NORMAL`

	flows := parseFlows(input)

	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}

	f := flows[0]

	if f.Cookie != "0x0" {
		t.Errorf("cookie: got %q, want 0x0", f.Cookie)
	}
	if f.Table != 0 {
		t.Errorf("table: got %d, want 0", f.Table)
	}
	if f.Packets != 734592734 {
		t.Errorf("packets: got %d, want 734592734", f.Packets)
	}
	if f.Bytes != 4075072624557 {
		t.Errorf("bytes: got %d, want 4075072624557", f.Bytes)
	}
	if f.Priority != 0 {
		t.Errorf("priority: got %d, want 0", f.Priority)
	}
	if f.Actions != "NORMAL" {
		t.Errorf("actions: got %q, want NORMAL", f.Actions)
	}
	if f.Age != "588418.364s" {
		t.Errorf("age: got %q, want 588418.364s", f.Age)
	}
}

func TestParseFlowsWithMatch(t *testing.T) {
	input := `OFPST_FLOW reply:
 cookie=0x1234, duration=100.5s, table=1, n_packets=1000, n_bytes=50000, priority=100,in_port=1,dl_type=0x0800 actions=output:2
 cookie=0x5678, duration=200.0s, table=2, n_packets=500, n_bytes=25000, priority=50,ip,nw_src=10.0.0.0/8 actions=drop`

	flows := parseFlows(input)

	if len(flows) != 2 {
		t.Fatalf("expected 2 flows, got %d", len(flows))
	}

	// First flow
	f1 := flows[0]
	if f1.Priority != 100 {
		t.Errorf("f1 priority: got %d, want 100", f1.Priority)
	}
	if f1.Match != "in_port=1,dl_type=0x0800" {
		t.Errorf("f1 match: got %q, want in_port=1,dl_type=0x0800", f1.Match)
	}
	if f1.Actions != "output:2" {
		t.Errorf("f1 actions: got %q, want output:2", f1.Actions)
	}

	// Second flow
	f2 := flows[1]
	if f2.Priority != 50 {
		t.Errorf("f2 priority: got %d, want 50", f2.Priority)
	}
	if f2.Actions != "drop" {
		t.Errorf("f2 actions: got %q, want drop", f2.Actions)
	}
}

func TestExtractMatch(t *testing.T) {
	tests := []struct {
		line     string
		expected string
	}{
		{
			"priority=0 actions=NORMAL",
			"*",
		},
		{
			"priority=100,in_port=1 actions=output:2",
			"in_port=1",
		},
		{
			"priority=100,in_port=1,dl_type=0x0800 actions=output:2",
			"in_port=1,dl_type=0x0800",
		},
	}

	for _, tt := range tests {
		got := extractMatch(tt.line)
		if got != tt.expected {
			t.Errorf("extractMatch(%q): got %q, want %q", tt.line, got, tt.expected)
		}
	}
}
