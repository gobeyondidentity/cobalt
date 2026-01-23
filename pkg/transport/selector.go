package transport

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
)

// DefaultTmfifoPath is the standard location for the tmfifo_net device on hosts.
const DefaultTmfifoPath = "/dev/tmfifo_net0"

// Config contains options for transport selection and initialization.
type Config struct {
	// MockTransport, if non-nil, is returned directly by NewHostTransport.
	// Used for test injection to bypass hardware detection.
	MockTransport Transport

	// TmfifoPath overrides the default tmfifo device path.
	// If empty, DefaultTmfifoPath is used for device detection.
	TmfifoPath string

	// InviteCode is the one-time code for network transport authentication.
	// Required when using NetworkTransport as a fallback.
	InviteCode string

	// DPUAddr is the network address of the DPU agent (host:port).
	// Required for NetworkTransport.
	DPUAddr string

	// TLSConfig provides TLS settings for NetworkTransport.
	// If nil, a default configuration with system roots is used.
	TLSConfig *tls.Config

	// Hostname is the host's name, used for identification in network transport.
	Hostname string

	// ForceTmfifo, if true, requires tmfifo transport and fails if unavailable.
	// When set, network fallback is disabled.
	ForceTmfifo bool

	// ForceNetwork, if true, skips hardware transport detection and uses network.
	// Requires InviteCode and DPUAddr to be set.
	ForceNetwork bool

	// ForceComCh, if true, requires DOCA ComCh transport and fails if unavailable.
	// When set, tmfifo and network fallback are disabled.
	ForceComCh bool

	// DOCADeviceName is the DOCA device name for ComCh transport.
	// If empty, the default device is used.
	DOCADeviceName string

	// DOCAServerName is the DOCA server name for ComCh transport.
	// Used to identify the DPU service to connect to.
	DOCAServerName string

	// DOCAPCIAddr is the PCI address of the DOCA device on the DPU (e.g., "03:00.0").
	// Used by NewDPUTransportListener for ComCh server creation.
	DOCAPCIAddr string

	// DOCARepPCIAddr is the representor PCI address for the host device (e.g., "01:00.0").
	// Used by NewDPUTransportListener for ComCh server creation.
	DOCARepPCIAddr string

	// KeyPath is the path to the Ed25519 keypair file for authentication.
	// If the file does not exist, a new keypair is generated.
	// Used by AuthClient for ComCh authentication.
	KeyPath string
}

// NewHostTransport creates a transport for the Host Agent to communicate with the DPU.
// Transport selection follows this priority (unless force flags are set):
//  1. MockTransport from config (test injection)
//  2. DOCA Comch if available (BlueField production)
//  3. TmfifoNet if device exists (BlueField legacy/emulator)
//  4. Network if invite code provided (non-BlueField fallback)
//
// If ForceComCh is set, only DOCA ComCh is tried and an error is returned if unavailable.
// If ForceTmfifo is set, only tmfifo is tried and an error is returned if unavailable.
// If ForceNetwork is set, hardware detection is skipped and network transport is used.
//
// Returns an error if no suitable transport is available.
func NewHostTransport(cfg *Config) (Transport, error) {
	if cfg == nil {
		cfg = &Config{}
	}

	// Priority 1: Mock transport for testing
	if cfg.MockTransport != nil {
		return cfg.MockTransport, nil
	}

	// Handle ForceNetwork: skip hardware detection
	if cfg.ForceNetwork {
		if cfg.DPUAddr == "" {
			return nil, errors.New("ForceNetwork requires DPUAddr to be set")
		}
		return NewNetworkTransport(cfg.DPUAddr, cfg.InviteCode, cfg.TLSConfig, cfg.Hostname)
	}

	// Handle ForceComCh: only try DOCA ComCh, fail if unavailable
	if cfg.ForceComCh {
		if !DOCAComchAvailable() {
			return nil, errors.New("DOCA ComCh not available (required by ForceComCh)")
		}
		clientCfg := DOCAComchClientConfig{
			PCIAddr:    cfg.DOCAPCIAddr,
			ServerName: cfg.DOCAServerName,
		}
		return NewDOCAComchClient(clientCfg)
	}

	// Determine tmfifo path
	tmfifoPath := cfg.TmfifoPath
	if tmfifoPath == "" {
		tmfifoPath = DefaultTmfifoPath
	}

	// Handle ForceTmfifo: only try tmfifo, fail if unavailable
	if cfg.ForceTmfifo {
		if _, err := os.Stat(tmfifoPath); err != nil {
			return nil, fmt.Errorf("tmfifo not available at %s (required by ForceTmfifo): %w", tmfifoPath, err)
		}
		return NewTmfifoNetTransport(tmfifoPath)
	}

	// Priority 2: DOCA Comch (preferred on BlueField)
	if DOCAComchAvailable() && cfg.DOCAPCIAddr != "" {
		clientCfg := DOCAComchClientConfig{
			PCIAddr:    cfg.DOCAPCIAddr,
			ServerName: cfg.DOCAServerName,
		}
		return NewDOCAComchClient(clientCfg)
	}

	// Priority 3: Tmfifo device (legacy BlueField or emulator)
	if _, err := os.Stat(tmfifoPath); err == nil {
		return NewTmfifoNetTransport(tmfifoPath)
	}

	// Priority 4: Network transport (non-BlueField fallback)
	// DPUAddr is required; InviteCode is optional (legacy HTTP mode doesn't use it)
	if cfg.DPUAddr != "" {
		return NewNetworkTransport(cfg.DPUAddr, cfg.InviteCode, cfg.TLSConfig, cfg.Hostname)
	}

	return nil, errors.New("no transport available: DOCA Comch not present, tmfifo device not found, and no DPU address provided")
}

// DOCAComchAvailable checks if the DOCA Comch transport can be used.
// Returns true only on systems with BlueField hardware and DOCA SDK.
// This is a placeholder; the actual implementation is in doca_comch.go.
func DOCAComchAvailable() bool {
	return docaComchAvailable()
}

// NewDPUTransportListener creates a transport listener for DPU agents.
// Transport selection follows this priority (unless force flags are set):
//  1. DOCA ComCh if available (BlueField production)
//  2. TmfifoNet if device exists (BlueField legacy/emulator)
//  3. Network if DPUAddr provided (non-BlueField fallback, listens on addr)
//
// If ForceComCh is set, only DOCA ComCh is tried and an error is returned if unavailable.
// If ForceTmfifo is set, only tmfifo is tried and an error is returned if unavailable.
// If ForceNetwork is set, hardware detection is skipped and network listener is created.
//
// Returns an error if no suitable transport listener is available.
func NewDPUTransportListener(cfg *Config) (TransportListener, error) {
	if cfg == nil {
		cfg = &Config{}
	}

	// Handle ForceNetwork: skip hardware detection
	if cfg.ForceNetwork {
		if cfg.DPUAddr == "" {
			return nil, errors.New("ForceNetwork requires DPUAddr to be set")
		}
		return NewNetworkListener(cfg.DPUAddr, cfg.TLSConfig)
	}

	// Handle ForceComCh: only try DOCA ComCh, fail if unavailable
	if cfg.ForceComCh {
		if !DOCAComchAvailable() {
			return nil, errors.New("DOCA ComCh not available (required by ForceComCh)")
		}
		serverCfg := DOCAComchServerConfig{
			PCIAddr:    cfg.DOCAPCIAddr,
			RepPCIAddr: cfg.DOCARepPCIAddr,
			ServerName: cfg.DOCAServerName,
		}
		return NewDOCAComchServer(serverCfg)
	}

	// Determine tmfifo path
	tmfifoPath := cfg.TmfifoPath
	if tmfifoPath == "" {
		tmfifoPath = DefaultTmfifoPath
	}

	// Handle ForceTmfifo: only try tmfifo, fail if unavailable
	if cfg.ForceTmfifo {
		if _, err := os.Stat(tmfifoPath); err != nil {
			return nil, fmt.Errorf("tmfifo not available at %s (required by ForceTmfifo): %w", tmfifoPath, err)
		}
		return NewTmfifoNetListener(tmfifoPath)
	}

	// Priority 1: DOCA ComCh (preferred on BlueField)
	if DOCAComchAvailable() {
		serverCfg := DOCAComchServerConfig{
			PCIAddr:    cfg.DOCAPCIAddr,
			RepPCIAddr: cfg.DOCARepPCIAddr,
			ServerName: cfg.DOCAServerName,
		}
		return NewDOCAComchServer(serverCfg)
	}

	// Priority 2: Tmfifo device (legacy BlueField or emulator)
	if _, err := os.Stat(tmfifoPath); err == nil {
		return NewTmfifoNetListener(tmfifoPath)
	}

	// Priority 3: Network listener (non-BlueField fallback)
	if cfg.DPUAddr != "" {
		return NewNetworkListener(cfg.DPUAddr, cfg.TLSConfig)
	}

	return nil, errors.New("no transport listener available: DOCA ComCh not present, tmfifo device not found, and no DPU address provided")
}
