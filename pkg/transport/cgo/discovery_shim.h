//go:build doca

// discovery_shim.h - C shim layer for DOCA device discovery
// Provides thin wrappers around DOCA device enumeration for CGO.

#ifndef DISCOVERY_SHIM_H
#define DISCOVERY_SHIM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Error codes for discovery operations
typedef enum {
    SHIM_DISCOVERY_OK = 0,
    SHIM_DISCOVERY_ERR_NO_DEVICES = -1,
    SHIM_DISCOVERY_ERR_ENUM_FAILED = -2,
    SHIM_DISCOVERY_ERR_BUFFER_TOO_SMALL = -3,
    SHIM_DISCOVERY_ERR_DEVICE_NOT_FOUND = -4,
    SHIM_DISCOVERY_ERR_CAPABILITY_CHECK = -5
} shim_discovery_error_t;

// shim_discover_devices enumerates all DOCA devices and returns JSON.
// Arguments:
//   buf: Buffer to write JSON result
//   buf_size: Size of buffer in bytes
// Returns: Number of devices found, or negative error code
// JSON format: [{"pci_addr":"01:00.0","ibdev_name":"mlx5_0",...},...]
int shim_discover_devices(char *buf, size_t buf_size);

// shim_check_comch_client_cap checks if device supports ComCh client.
// Arguments:
//   pci_addr: PCI address of the device (e.g., "01:00.0")
// Returns: 1 if supported, 0 if not supported, negative on error
int shim_check_comch_client_cap(const char *pci_addr);

// shim_check_comch_server_cap checks if device supports ComCh server.
// Arguments:
//   pci_addr: PCI address of the device (e.g., "01:00.0")
// Returns: 1 if supported, 0 if not supported, negative on error
int shim_check_comch_server_cap(const char *pci_addr);

#ifdef __cplusplus
}
#endif

#endif // DISCOVERY_SHIM_H
