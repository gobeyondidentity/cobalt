// Package posture provides Linux host security posture collection.
package posture

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Posture contains security posture information collected from a Linux host.
type Posture struct {
	SecureBoot     *bool  `json:"secure_boot"`
	DiskEncryption string `json:"disk_encryption"` // "luks", "none", ""
	OSVersion      string `json:"os_version"`
	KernelVersion  string `json:"kernel_version"`
	TPMPresent     *bool  `json:"tpm_present"`
}

// Collect gathers security posture from the current host.
// This function is designed for Linux systems; on other platforms,
// some fields may be empty or nil.
func Collect() *Posture {
	p := &Posture{}
	p.SecureBoot = detectSecureBoot()
	p.DiskEncryption = detectDiskEncryption()
	p.OSVersion = detectOSVersion()
	p.KernelVersion = detectKernelVersion()
	p.TPMPresent = detectTPM()
	return p
}

// Hash computes a deterministic SHA256 hash of the posture data.
// The hash is computed from a canonical string representation of the fields,
// sorted alphabetically by field name.
func (p *Posture) Hash() string {
	data := fmt.Sprintf("disk_encryption=%s,kernel_version=%s,os_version=%s,secure_boot=%s,tpm_present=%s",
		p.DiskEncryption, p.KernelVersion, p.OSVersion, boolStr(p.SecureBoot), boolStr(p.TPMPresent))
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// boolStr converts a *bool to a string representation for hashing.
func boolStr(b *bool) string {
	if b == nil {
		return "nil"
	}
	return fmt.Sprintf("%v", *b)
}

// detectSecureBoot checks if Secure Boot is enabled on a UEFI system.
// Returns nil if UEFI is not available or Secure Boot status cannot be determined.
func detectSecureBoot() *bool {
	// Look for SecureBoot EFI variable
	// The variable name includes a GUID: SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
	files, err := filepath.Glob("/sys/firmware/efi/efivars/SecureBoot-*")
	if err != nil || len(files) == 0 {
		return nil // UEFI not available or no SecureBoot variable
	}

	// Read the SecureBoot variable
	// Format: 4-byte attributes + 1-byte value
	data, err := os.ReadFile(files[0])
	if err != nil || len(data) < 5 {
		return nil
	}

	// The 5th byte (index 4) indicates Secure Boot status: 1 = enabled
	enabled := data[4] == 1
	return &enabled
}

// detectDiskEncryption checks for LUKS encrypted volumes.
// Returns "luks" if encrypted volumes are found, "none" if no encryption, "" on error.
func detectDiskEncryption() string {
	// Use lsblk to check for crypt type devices
	out, err := exec.Command("lsblk", "-o", "TYPE", "-n").Output()
	if err != nil {
		return ""
	}

	if strings.Contains(string(out), "crypt") {
		return "luks"
	}
	return "none"
}

// detectOSVersion reads the PRETTY_NAME from /etc/os-release.
func detectOSVersion() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			value := strings.TrimPrefix(line, "PRETTY_NAME=")
			return strings.Trim(value, "\"")
		}
	}
	return ""
}

// detectKernelVersion runs uname -r to get the kernel version.
func detectKernelVersion() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// detectTPM checks for the presence of a TPM device.
// Returns a pointer to true if TPM is present, false if confirmed absent, nil if unknown.
func detectTPM() *bool {
	// Check for TPM 2.0 resource manager device
	if _, err := os.Stat("/dev/tpmrm0"); err == nil {
		t := true
		return &t
	}

	// Check for TPM 2.0 device
	if _, err := os.Stat("/dev/tpm0"); err == nil {
		t := true
		return &t
	}

	// No TPM device found
	f := false
	return &f
}
