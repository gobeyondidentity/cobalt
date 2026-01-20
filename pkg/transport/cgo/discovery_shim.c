// discovery_shim.c - C shim layer for DOCA device discovery
// Provides thin wrappers around DOCA device enumeration for CGO.

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <doca_comch.h>
#include <doca_dev.h>
#include <doca_error.h>
#include <doca_log.h>

#include "discovery_shim.h"

DOCA_LOG_REGISTER(DISCOVERY_SHIM);

// Helper: Get PCI function type value
static int get_pci_func_type(struct doca_devinfo *devinfo) {
    enum doca_pci_func_type func_type;
    doca_error_t result = doca_devinfo_get_pci_func_type(devinfo, &func_type);
    if (result != DOCA_SUCCESS) {
        return -1;
    }
    return (int)func_type;
}

// Helper: Check if device supports ComCh client
static int check_comch_client_support(struct doca_devinfo *devinfo) {
    doca_error_t result = doca_comch_cap_client_is_supported(devinfo);
    return (result == DOCA_SUCCESS) ? 1 : 0;
}

// Helper: Check if device supports ComCh server
static int check_comch_server_support(struct doca_devinfo *devinfo) {
    doca_error_t result = doca_comch_cap_server_is_supported(devinfo);
    return (result == DOCA_SUCCESS) ? 1 : 0;
}

int shim_discover_devices(char *buf, size_t buf_size) {
    struct doca_devinfo **dev_list = NULL;
    uint32_t nb_devs = 0;
    doca_error_t result;
    int device_count = 0;
    size_t offset = 0;

    if (buf == NULL || buf_size == 0) {
        return SHIM_DISCOVERY_ERR_ENUM_FAILED;
    }

    // Create device list
    result = doca_devinfo_create_list(&dev_list, &nb_devs);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create device list: %s", doca_error_get_descr(result));
        return SHIM_DISCOVERY_ERR_ENUM_FAILED;
    }

    if (nb_devs == 0) {
        doca_devinfo_destroy_list(dev_list);
        return SHIM_DISCOVERY_ERR_NO_DEVICES;
    }

    // Start JSON array
    offset += snprintf(buf + offset, buf_size - offset, "[");

    // Enumerate devices
    for (uint32_t i = 0; i < nb_devs && offset < buf_size - 1; i++) {
        char pci_addr[DOCA_DEVINFO_PCI_ADDR_SIZE] = {0};
        char ibdev_name[DOCA_DEVINFO_IBDEV_NAME_SIZE] = {0};
        char iface_name[DOCA_DEVINFO_IFACE_NAME_SIZE] = {0};

        // Get PCI address
        result = doca_devinfo_get_pci_addr_str(dev_list[i], pci_addr);
        if (result != DOCA_SUCCESS) {
            continue;
        }

        // Get IB device name (optional)
        result = doca_devinfo_get_ibdev_name(dev_list[i], ibdev_name, sizeof(ibdev_name));
        if (result != DOCA_SUCCESS) {
            ibdev_name[0] = '\0';
        }

        // Get interface name (optional)
        result = doca_devinfo_get_iface_name(dev_list[i], iface_name, sizeof(iface_name));
        if (result != DOCA_SUCCESS) {
            iface_name[0] = '\0';
        }

        // Get function type
        int func_type = get_pci_func_type(dev_list[i]);
        if (func_type < 0) {
            func_type = 0; // Default to PF if unknown
        }

        // Check capabilities
        int is_client = check_comch_client_support(dev_list[i]);
        int is_server = check_comch_server_support(dev_list[i]);

        // Add comma separator for non-first entries
        if (device_count > 0) {
            offset += snprintf(buf + offset, buf_size - offset, ",");
        }

        // Write JSON object for this device
        int written = snprintf(buf + offset, buf_size - offset,
            "{\"pci_addr\":\"%s\",\"ibdev_name\":\"%s\",\"iface_name\":\"%s\","
            "\"func_type\":%d,\"is_comch_client\":%s,\"is_comch_server\":%s}",
            pci_addr, ibdev_name, iface_name, func_type,
            is_client ? "true" : "false",
            is_server ? "true" : "false");

        if (written < 0 || (size_t)written >= buf_size - offset) {
            DOCA_LOG_WARN("Buffer too small for all devices");
            break;
        }

        offset += written;
        device_count++;
    }

    // Close JSON array
    if (offset < buf_size - 1) {
        offset += snprintf(buf + offset, buf_size - offset, "]");
    }

    doca_devinfo_destroy_list(dev_list);

    DOCA_LOG_INFO("Discovered %d DOCA devices", device_count);
    return device_count;
}

int shim_check_comch_client_cap(const char *pci_addr) {
    struct doca_devinfo **dev_list = NULL;
    uint32_t nb_devs = 0;
    doca_error_t result;
    int cap_result = SHIM_DISCOVERY_ERR_DEVICE_NOT_FOUND;
    char pci_buf[DOCA_DEVINFO_PCI_ADDR_SIZE];

    if (pci_addr == NULL) {
        return SHIM_DISCOVERY_ERR_CAPABILITY_CHECK;
    }

    result = doca_devinfo_create_list(&dev_list, &nb_devs);
    if (result != DOCA_SUCCESS) {
        return SHIM_DISCOVERY_ERR_ENUM_FAILED;
    }

    for (uint32_t i = 0; i < nb_devs; i++) {
        result = doca_devinfo_get_pci_addr_str(dev_list[i], pci_buf);
        if (result != DOCA_SUCCESS) {
            continue;
        }

        if (strcmp(pci_buf, pci_addr) == 0) {
            cap_result = check_comch_client_support(dev_list[i]);
            break;
        }
    }

    doca_devinfo_destroy_list(dev_list);
    return cap_result;
}

int shim_check_comch_server_cap(const char *pci_addr) {
    struct doca_devinfo **dev_list = NULL;
    uint32_t nb_devs = 0;
    doca_error_t result;
    int cap_result = SHIM_DISCOVERY_ERR_DEVICE_NOT_FOUND;
    char pci_buf[DOCA_DEVINFO_PCI_ADDR_SIZE];

    if (pci_addr == NULL) {
        return SHIM_DISCOVERY_ERR_CAPABILITY_CHECK;
    }

    result = doca_devinfo_create_list(&dev_list, &nb_devs);
    if (result != DOCA_SUCCESS) {
        return SHIM_DISCOVERY_ERR_ENUM_FAILED;
    }

    for (uint32_t i = 0; i < nb_devs; i++) {
        result = doca_devinfo_get_pci_addr_str(dev_list[i], pci_buf);
        if (result != DOCA_SUCCESS) {
            continue;
        }

        if (strcmp(pci_buf, pci_addr) == 0) {
            cap_result = check_comch_server_support(dev_list[i]);
            break;
        }
    }

    doca_devinfo_destroy_list(dev_list);
    return cap_result;
}
