//go:build !doca

package transport

import (
	"context"
	"errors"
)

// docaComchAvailable returns false on systems without DOCA SDK.
func docaComchAvailable() bool {
	return false
}

// NewDOCAComchTransport returns an error on systems without DOCA SDK.
// The real implementation requires BlueField hardware and DOCA libraries.
func NewDOCAComchTransport() (Transport, error) {
	return nil, ErrDOCANotAvailable
}

// ============================================================================
// Client Stubs
// ============================================================================

// DOCAComchClientConfig holds configuration for DOCA ComCh client.
// This stub exists for non-DOCA builds to allow code that references
// the config type to compile.
type DOCAComchClientConfig struct {
	PCIAddr        string
	ServerName     string
	MaxMsgSize     uint32
	RecvBufferSize int
}

// DOCAComchClient is a stub for non-DOCA builds.
// The real implementation requires BlueField hardware and DOCA SDK.
type DOCAComchClient struct{}

// NewDOCAComchClient returns an error on systems without DOCA SDK.
func NewDOCAComchClient(cfg DOCAComchClientConfig) (*DOCAComchClient, error) {
	return nil, ErrDOCANotAvailable
}

// Connect returns an error on systems without DOCA SDK.
func (c *DOCAComchClient) Connect(ctx context.Context) error {
	return ErrDOCANotAvailable
}

// Send returns an error on systems without DOCA SDK.
func (c *DOCAComchClient) Send(msg *Message) error {
	return ErrDOCANotAvailable
}

// Recv returns an error on systems without DOCA SDK.
func (c *DOCAComchClient) Recv() (*Message, error) {
	return nil, ErrDOCANotAvailable
}

// Close is a no-op on systems without DOCA SDK.
func (c *DOCAComchClient) Close() error {
	return nil
}

// Type returns TransportDOCAComch.
func (c *DOCAComchClient) Type() TransportType {
	return TransportDOCAComch
}

// State returns "unavailable" on systems without DOCA SDK.
func (c *DOCAComchClient) State() string {
	return "unavailable"
}

// MaxMsgSize returns 0 on systems without DOCA SDK.
func (c *DOCAComchClient) MaxMsgSize() uint32 {
	return 0
}

// ============================================================================
// Server Stubs
// ============================================================================

// DOCAComchServerConfig holds configuration for DOCA ComCh server.
// This stub exists for non-DOCA builds to allow code that references
// the config type to compile.
type DOCAComchServerConfig struct {
	PCIAddr        string
	RepPCIAddr     string
	ServerName     string
	MaxMsgSize     uint32
	RecvBufferSize int
	MaxClients     int
}

// DOCAComchServer is a stub for non-DOCA builds.
// The real implementation requires BlueField hardware and DOCA SDK.
type DOCAComchServer struct{}

// validateServerConfig validates the server configuration.
// In stub mode, this just checks required fields are present.
func validateServerConfig(cfg DOCAComchServerConfig) error {
	if cfg.PCIAddr == "" {
		return errors.New("doca comch server: PCI address required")
	}
	if cfg.RepPCIAddr == "" {
		return errors.New("doca comch server: representor PCI address required")
	}
	if cfg.ServerName == "" {
		return errors.New("doca comch server: server name required")
	}
	return nil
}

// NewDOCAComchServer returns an error on systems without DOCA SDK.
func NewDOCAComchServer(cfg DOCAComchServerConfig) (*DOCAComchServer, error) {
	return nil, ErrDOCANotAvailable
}

// Accept returns an error on systems without DOCA SDK.
func (s *DOCAComchServer) Accept() (Transport, error) {
	return nil, ErrDOCANotAvailable
}

// Close is a no-op on systems without DOCA SDK.
func (s *DOCAComchServer) Close() error {
	return nil
}

// Type returns TransportDOCAComch.
func (s *DOCAComchServer) Type() TransportType {
	return TransportDOCAComch
}

// DOCAComchServerConn is a stub for non-DOCA builds.
// Represents a single client connection on the server.
type DOCAComchServerConn struct{}

// Connect returns an error on systems without DOCA SDK.
func (c *DOCAComchServerConn) Connect(ctx context.Context) error {
	return ErrDOCANotAvailable
}

// Send returns an error on systems without DOCA SDK.
func (c *DOCAComchServerConn) Send(msg *Message) error {
	return ErrDOCANotAvailable
}

// Recv returns an error on systems without DOCA SDK.
func (c *DOCAComchServerConn) Recv() (*Message, error) {
	return nil, ErrDOCANotAvailable
}

// Close is a no-op on systems without DOCA SDK.
func (c *DOCAComchServerConn) Close() error {
	return nil
}

// Type returns TransportDOCAComch.
func (c *DOCAComchServerConn) Type() TransportType {
	return TransportDOCAComch
}

// State returns "unavailable" on systems without DOCA SDK.
func (c *DOCAComchServerConn) State() string {
	return "unavailable"
}

// MaxMessageSize returns 0 on systems without DOCA SDK.
func (c *DOCAComchServerConn) MaxMessageSize() uint32 {
	return 0
}

// ============================================================================
// PCI Discovery Stubs
// ============================================================================

// PCIFuncType represents the PCI function type from DOCA API.
type PCIFuncType int

const (
	// PCIFuncTypePF is a Physical Function (preferred for ComCh)
	PCIFuncTypePF PCIFuncType = 0
	// PCIFuncTypeVF is a Virtual Function
	PCIFuncTypeVF PCIFuncType = 1
	// PCIFuncTypeSF is a Sub Function
	PCIFuncTypeSF PCIFuncType = 2
)

// String returns a human-readable function type name.
func (t PCIFuncType) String() string {
	switch t {
	case PCIFuncTypePF:
		return "PF"
	case PCIFuncTypeVF:
		return "VF"
	case PCIFuncTypeSF:
		return "SF"
	default:
		return "unknown"
	}
}

// DeviceInfo contains information about a discovered DOCA device.
// This stub exists for non-DOCA builds.
type DeviceInfo struct {
	// PCIAddr is the PCI address (e.g., "01:00.0")
	PCIAddr string `json:"pci_addr"`

	// IbdevName is the InfiniBand device name (e.g., "mlx5_0")
	IbdevName string `json:"ibdev_name"`

	// IfaceName is the network interface name (e.g., "enp1s0f0np0")
	IfaceName string `json:"iface_name"`

	// FuncType is the PCI function type (PF, VF, or SF)
	FuncType PCIFuncType `json:"func_type"`

	// IsComchClient indicates if this device supports ComCh client operations (host side)
	IsComchClient bool `json:"is_comch_client"`

	// IsComchServer indicates if this device supports ComCh server operations (DPU side)
	IsComchServer bool `json:"is_comch_server"`
}

// DeviceSelectionConfig configures automatic device selection.
type DeviceSelectionConfig struct {
	// PCIAddrOverride forces selection of a specific PCI address.
	PCIAddrOverride string

	// PreferPort prefers devices with this port number (0 or 1).
	PreferPort int

	// RequireClient requires the device to support ComCh client operations.
	RequireClient bool

	// RequireServer requires the device to support ComCh server operations.
	RequireServer bool
}

// DefaultDeviceSelectionConfig returns a DeviceSelectionConfig with sensible defaults.
func DefaultDeviceSelectionConfig() DeviceSelectionConfig {
	return DeviceSelectionConfig{
		PCIAddrOverride: "",
		PreferPort:      0,
		RequireClient:   false,
		RequireServer:   false,
	}
}

// DiscoverDOCADevices returns an error on systems without DOCA SDK.
func DiscoverDOCADevices() ([]DeviceInfo, error) {
	return nil, ErrDOCANotAvailable
}

// SelectDevice returns an error on systems without DOCA SDK.
func SelectDevice(cfg DeviceSelectionConfig) (*DeviceInfo, error) {
	return nil, ErrDOCANotAvailable
}

// CheckComchClientCapability returns an error on systems without DOCA SDK.
func CheckComchClientCapability(pciAddr string) (bool, error) {
	return false, ErrDOCANotAvailable
}

// CheckComchServerCapability returns an error on systems without DOCA SDK.
func CheckComchServerCapability(pciAddr string) (bool, error) {
	return false, ErrDOCANotAvailable
}
