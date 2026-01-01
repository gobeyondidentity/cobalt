// Package ovs provides a client for interacting with Open vSwitch on the DPU.
// It wraps ovs-vsctl and ovs-ofctl commands for bridge and flow management.
package ovs

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Client provides OVS operations
type Client struct {
	useSudo bool
}

// NewClient creates a new OVS client.
// Uses sudo by default since OVS commands require root on BlueField.
func NewClient() *Client {
	return &Client{
		useSudo: true,
	}
}

// cmd builds a command with optional sudo prefix
func (c *Client) cmd(ctx context.Context, name string, args ...string) *exec.Cmd {
	if c.useSudo {
		return exec.CommandContext(ctx, "sudo", append([]string{name}, args...)...)
	}
	return exec.CommandContext(ctx, name, args...)
}

// Bridge represents an OVS bridge
type Bridge struct {
	Name  string   `json:"name"`
	Ports []string `json:"ports"`
}

// Flow represents an OVS flow entry
type Flow struct {
	Cookie   string `json:"cookie"`
	Table    int    `json:"table"`
	Priority int    `json:"priority"`
	Match    string `json:"match"`
	Actions  string `json:"actions"`
	Packets  int64  `json:"packets"`
	Bytes    int64  `json:"bytes"`
	Age      string `json:"age"`
}

// ListBridges returns all OVS bridges with their ports
func (c *Client) ListBridges(ctx context.Context) ([]Bridge, error) {
	out, err := c.cmd(ctx, "ovs-vsctl", "list-br").Output()
	if err != nil {
		return nil, err
	}

	var bridges []Bridge
	for _, name := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if name == "" {
			continue
		}

		bridge := Bridge{Name: name}

		// Get ports for this bridge
		portsOut, err := c.cmd(ctx, "ovs-vsctl", "list-ports", name).Output()
		if err == nil {
			for _, port := range strings.Split(strings.TrimSpace(string(portsOut)), "\n") {
				if port != "" {
					bridge.Ports = append(bridge.Ports, port)
				}
			}
		}

		bridges = append(bridges, bridge)
	}

	return bridges, nil
}

// GetFlows returns flows for a bridge
func (c *Client) GetFlows(ctx context.Context, bridge string) ([]Flow, error) {
	out, err := c.cmd(ctx, "ovs-ofctl", "dump-flows", bridge).Output()
	if err != nil {
		return nil, err
	}

	return parseFlows(string(out)), nil
}

// parseFlows parses ovs-ofctl dump-flows output into structured Flow objects.
// Example line:
// cookie=0x0, duration=588418.364s, table=0, n_packets=734592734, n_bytes=4075072624557, idle_age=16, hard_age=65534, priority=0 actions=NORMAL
func parseFlows(output string) []Flow {
	var flows []Flow

	// Patterns for extracting flow fields
	cookieRe := regexp.MustCompile(`cookie=([^,]+)`)
	tableRe := regexp.MustCompile(`table=(\d+)`)
	packetsRe := regexp.MustCompile(`n_packets=(\d+)`)
	bytesRe := regexp.MustCompile(`n_bytes=(\d+)`)
	durationRe := regexp.MustCompile(`duration=([^,]+)`)
	priorityRe := regexp.MustCompile(`priority=(\d+)`)
	actionsRe := regexp.MustCompile(`actions=(.+)$`)

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)

		// Skip header lines and empty lines
		if line == "" || strings.HasPrefix(line, "NXST_FLOW") || strings.HasPrefix(line, "OFPST_FLOW") {
			continue
		}

		flow := Flow{}

		// Extract cookie
		if m := cookieRe.FindStringSubmatch(line); len(m) > 1 {
			flow.Cookie = m[1]
		}

		// Extract table
		if m := tableRe.FindStringSubmatch(line); len(m) > 1 {
			flow.Table, _ = strconv.Atoi(m[1])
		}

		// Extract packets
		if m := packetsRe.FindStringSubmatch(line); len(m) > 1 {
			flow.Packets, _ = strconv.ParseInt(m[1], 10, 64)
		}

		// Extract bytes
		if m := bytesRe.FindStringSubmatch(line); len(m) > 1 {
			flow.Bytes, _ = strconv.ParseInt(m[1], 10, 64)
		}

		// Extract duration as age
		if m := durationRe.FindStringSubmatch(line); len(m) > 1 {
			flow.Age = m[1]
		}

		// Extract priority
		if m := priorityRe.FindStringSubmatch(line); len(m) > 1 {
			flow.Priority, _ = strconv.Atoi(m[1])
		}

		// Extract actions
		if m := actionsRe.FindStringSubmatch(line); len(m) > 1 {
			flow.Actions = m[1]
		}

		// Extract match criteria (everything between priority and actions)
		// This is the tricky part as match fields vary
		flow.Match = extractMatch(line)

		flows = append(flows, flow)
	}

	return flows
}

// extractMatch extracts the match portion of a flow rule.
// Match is everything after "priority=N," (or "priority=N ") and before "actions="
func extractMatch(line string) string {
	// Find position after priority
	priorityIdx := strings.Index(line, "priority=")
	if priorityIdx == -1 {
		return ""
	}

	afterPriority := line[priorityIdx:]

	// Find where priority value ends (comma or space before actions)
	commaIdx := strings.Index(afterPriority, ",")
	spaceIdx := strings.Index(afterPriority, " ")

	var rest string
	if commaIdx != -1 {
		// There's a comma, so there might be match criteria
		rest = afterPriority[commaIdx+1:]
	} else if spaceIdx != -1 {
		// No comma after priority, check if there's anything before actions
		rest = afterPriority[spaceIdx+1:]
	} else {
		return "*"
	}

	// Find "actions=" and take everything before it
	actionsIdx := strings.Index(rest, "actions=")
	if actionsIdx == -1 {
		match := strings.TrimSpace(rest)
		if match == "" {
			return "*"
		}
		return match
	}

	match := strings.TrimSpace(rest[:actionsIdx])

	// Remove trailing comma if present
	match = strings.TrimSuffix(match, ",")
	match = strings.TrimSpace(match)

	// If match is empty, it means "match all"
	if match == "" {
		return "*"
	}

	return match
}

// GetVersion returns the OVS version (does not require sudo)
func (c *Client) GetVersion(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "ovs-vsctl", "--version").Output()
	if err != nil {
		return "", err
	}

	// Parse: "ovs-vsctl (Open vSwitch) 3.2.1005"
	lines := strings.Split(string(out), "\n")
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 4 {
			return parts[3], nil
		}
	}
	return "", nil
}
