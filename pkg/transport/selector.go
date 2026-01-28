package transport

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"os"
)

// DefaultTmfifoSocketPath is the default path for Unix socket emulation in tests.
// This is NOT a real device path; it's where socat creates a socket for testing.
const DefaultTmfifoSocketPath = "/tmp/tmfifo.sock"

// Config contains options for transport selection and initialization.
type Config struct {
	// MockTransport, if non-nil, is returned directly by NewHostTransport.
	// Used for test injection to bypass hardware detection.
	MockTransport Transport

	// TmfifoSocketPath is the path for Unix socket emulation (test mode).
	// If a Unix socket exists at this path, it will be used instead of TCP.
	TmfifoSocketPath string

	// TmfifoDPUAddr is the TCP address of the DPU for tmfifo connections.
	// Default: "192.168.100.2:9444"
	TmfifoDPUAddr string

	// TmfifoListenAddr is the TCP address to listen on for tmfifo connections (DPU side).
	// Default: ":9444" (all interfaces, port 9444)
	TmfifoListenAddr string

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

// hasEmulatedSocket checks if a Unix socket exists at the given path.
// This is used to detect test environments using socat emulation.
func hasEmulatedSocket(path string) bool {
	if path == "" {
		return false
	}
	return isUnixSocket(path)
}

// NewHostTransport creates a transport for the Host Agent to communicate with the DPU.
// Transport selection follows this priority (unless force flags are set):
//  1. MockTransport from config (test injection)
//  2. DOCA Comch if available (BlueField production)
//  3. Emulated socket if exists (test mode)
//  4. TmfifoNet TCP if tmfifo_net0 interface exists (BlueField hardware)
//  5. Network if DPU address provided (non-BlueField fallback)
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
		log.Printf("transport: using mock transport (test mode)")
		return cfg.MockTransport, nil
	}

	// Handle ForceNetwork: skip hardware detection
	if cfg.ForceNetwork {
		if cfg.DPUAddr == "" {
			return nil, errors.New("ForceNetwork requires DPUAddr to be set")
		}
		log.Printf("transport: forced network mode, connecting to %s", cfg.DPUAddr)
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
		log.Printf("transport: using DOCA ComCh (forced)")
		return NewDOCAComchClient(clientCfg)
	}

	// Handle ForceTmfifo: require tmfifo (emulated socket or interface)
	if cfg.ForceTmfifo {
		// Check for emulated socket first
		if hasEmulatedSocket(cfg.TmfifoSocketPath) {
			log.Printf("transport: using tmfifo Unix socket %s (forced, test mode)", cfg.TmfifoSocketPath)
			return NewTmfifoNetTransportWithSocket(cfg.TmfifoDPUAddr, cfg.TmfifoSocketPath)
		}
		// Check for real interface
		if hasTmfifoInterface() {
			dpuAddr := cfg.TmfifoDPUAddr
			if dpuAddr == "" {
				dpuAddr = TmfifoDefaultDPUAddr
			}
			log.Printf("transport: using tmfifo TCP to %s (forced)", dpuAddr)
			return NewTmfifoNetTransport(dpuAddr)
		}
		return nil, fmt.Errorf("tmfifo not available: no Unix socket at %s and no %s interface (required by ForceTmfifo)",
			cfg.TmfifoSocketPath, TmfifoInterfaceName)
	}

	// Priority 2: DOCA Comch (preferred on BlueField)
	if DOCAComchAvailable() && cfg.DOCAPCIAddr != "" {
		clientCfg := DOCAComchClientConfig{
			PCIAddr:    cfg.DOCAPCIAddr,
			ServerName: cfg.DOCAServerName,
		}
		log.Printf("transport: using DOCA ComCh")
		return NewDOCAComchClient(clientCfg)
	}

	// Priority 3: Emulated socket (test mode)
	if hasEmulatedSocket(cfg.TmfifoSocketPath) {
		log.Printf("transport: using tmfifo Unix socket %s (test mode)", cfg.TmfifoSocketPath)
		return NewTmfifoNetTransportWithSocket(cfg.TmfifoDPUAddr, cfg.TmfifoSocketPath)
	}

	// Priority 4: Tmfifo TCP (BlueField hardware)
	if hasTmfifoInterface() {
		dpuAddr := cfg.TmfifoDPUAddr
		if dpuAddr == "" {
			dpuAddr = TmfifoDefaultDPUAddr
		}
		log.Printf("transport: using tmfifo TCP to %s (interface %s detected)", dpuAddr, TmfifoInterfaceName)
		return NewTmfifoNetTransport(dpuAddr)
	}

	// Priority 5: Network transport (non-BlueField fallback)
	// DPUAddr is required; InviteCode is optional (legacy HTTP mode doesn't use it)
	if cfg.DPUAddr != "" {
		log.Printf("transport: using network transport to %s", cfg.DPUAddr)
		return NewNetworkTransport(cfg.DPUAddr, cfg.InviteCode, cfg.TLSConfig, cfg.Hostname)
	}

	return nil, errors.New("no transport available: DOCA ComCh not present, tmfifo interface not found, no emulated socket, and no DPU address provided")
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
//  2. Emulated socket if path provided (test mode)
//  3. TmfifoNet TCP listener (BlueField hardware or any system)
//  4. Network if DPUAddr provided (non-BlueField fallback, listens on addr)
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
		log.Printf("transport: network listener on %s (forced)", cfg.DPUAddr)
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
		log.Printf("transport: DOCA ComCh listener (forced)")
		return NewDOCAComchServer(serverCfg)
	}

	// Handle ForceTmfifo: require tmfifo listener
	if cfg.ForceTmfifo {
		// Check for emulated socket path
		if cfg.TmfifoSocketPath != "" {
			log.Printf("transport: tmfifo Unix socket listener at %s (forced, test mode)", cfg.TmfifoSocketPath)
			return NewTmfifoNetListenerWithSocket(cfg.TmfifoListenAddr, cfg.TmfifoSocketPath)
		}
		// Use TCP listener
		listenAddr := cfg.TmfifoListenAddr
		if listenAddr == "" {
			listenAddr = fmt.Sprintf(":%d", TmfifoListenPort)
		}
		log.Printf("transport: tmfifo TCP listener on %s (forced)", listenAddr)
		return NewTmfifoNetListener(listenAddr)
	}

	// Priority 1: DOCA ComCh (preferred on BlueField)
	if DOCAComchAvailable() {
		serverCfg := DOCAComchServerConfig{
			PCIAddr:    cfg.DOCAPCIAddr,
			RepPCIAddr: cfg.DOCARepPCIAddr,
			ServerName: cfg.DOCAServerName,
		}
		log.Printf("transport: DOCA ComCh listener")
		return NewDOCAComchServer(serverCfg)
	}

	// Priority 2: Emulated socket (test mode)
	if cfg.TmfifoSocketPath != "" {
		// For listener, we create the socket (don't check if it exists)
		log.Printf("transport: tmfifo Unix socket listener at %s (test mode)", cfg.TmfifoSocketPath)
		return NewTmfifoNetListenerWithSocket(cfg.TmfifoListenAddr, cfg.TmfifoSocketPath)
	}

	// Priority 3: Tmfifo TCP listener (BlueField hardware or configured)
	if hasTmfifoInterface() || cfg.TmfifoListenAddr != "" {
		listenAddr := cfg.TmfifoListenAddr
		if listenAddr == "" {
			listenAddr = fmt.Sprintf(":%d", TmfifoListenPort)
		}
		if hasTmfifoInterface() {
			log.Printf("transport: tmfifo TCP listener on %s (interface %s detected)", listenAddr, TmfifoInterfaceName)
		} else {
			log.Printf("transport: tmfifo TCP listener on %s", listenAddr)
		}
		return NewTmfifoNetListener(listenAddr)
	}

	// Priority 4: Network listener (non-BlueField fallback)
	if cfg.DPUAddr != "" {
		log.Printf("transport: network listener on %s", cfg.DPUAddr)
		return NewNetworkListener(cfg.DPUAddr, cfg.TLSConfig)
	}

	return nil, errors.New("no transport listener available: DOCA ComCh not present, no tmfifo socket path, no listen address, and no DPU address provided")
}

// Deprecated: DetectTmfifoDevice is deprecated. Use HasTmfifoInterface() instead.
// This function checked for device files, but tmfifo_net0 is a network interface, not a device.
func DetectTmfifoDevice() (string, bool) {
	// For backward compatibility, check if interface exists
	if hasTmfifoInterface() {
		return TmfifoInterfaceName, true
	}
	return "", false
}

// Deprecated: TmfifoDevicePaths is deprecated. tmfifo_net0 is a network interface, not a device file.
// This variable is kept for backward compatibility but should not be used.
var TmfifoDevicePaths = []string{}

// Deprecated: DefaultTmfifoPath is deprecated. Use TmfifoDefaultDPUAddr or TmfifoSocketPath instead.
// tmfifo_net0 is a network interface, not a device file.
const DefaultTmfifoPath = "/dev/tmfifo_net0"

// fileExists checks if a file exists at the given path.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
