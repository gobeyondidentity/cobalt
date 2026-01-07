// Package fixture handles loading and templating of DPU fixture data.
package fixture

import (
	agentv1 "github.com/nmelo/secure-infra/gen/go/agent/v1"
)

// DefaultFixture returns a minimal fixture with reasonable defaults for local development.
// This is used when no --fixture flag is provided, enabling quick startup without
// needing to specify a fixture file.
func DefaultFixture() *Fixture {
	return &Fixture{
		SystemInfo: &agentv1.GetSystemInfoResponse{
			Hostname:        "dpuemu-local",
			Model:           "Emulated BlueField-3",
			SerialNumber:    "EMU-00000001",
			FirmwareVersion: "emulated-1.0.0",
			DocaVersion:     "emulated",
			ArmCores:        16,
			MemoryGb:        32,
			UptimeSeconds:   0,
			OvsVersion:      "2.17.0",
			KernelVersion:   "emulated",
		},
		Bridges: []*agentv1.Bridge{},
		Flows:   make(map[string][]*agentv1.Flow),
		Attestation: &AttestationData{
			Status: "ATTESTATION_STATUS_VALID",
			Certificates: []*CertData{
				{
					Level:             0,
					Subject:           "CN=DPU Device Identity,O=NVIDIA,OU=BlueField-3",
					Issuer:            "CN=NVIDIA DICE Root CA,O=NVIDIA",
					NotBefore:         "2024-01-01T00:00:00Z",
					NotAfter:          "2034-01-01T00:00:00Z",
					Algorithm:         "ECDSA-P384",
					PEM:               "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIUEmulatedDICEL0CertificateData0000000wCgYIKoZIzj0EAwMw\nOjELMAkGA1UEBhMCVVMxDzANBgNVBAoMBk5WSURJQTEaMBgGA1UEAwwRTlZJRElB\nIERJQ0UgUm9vdCBDQTAeFw0yNDAxMDEwMDAwMDBaFw0zNDAxMDEwMDAwMDBaMEUx\nCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZOVklESUExJTAjBgNVBAMMHERQVSBEZXZp\nY2UgSWRlbnRpdHkgKEVtdWxhdGVkKTB2MBAGByqGSM49AgEGBSuBBAAiA2IABEmu\nlatedPublicKeyDataForTestingPurposesOnlyNotReal0000000000000000000w\nCgYIKoZIzj0EAwMDaAAwZQIwEmulatedSignatureData000000000000000000000\n-----END CERTIFICATE-----",
					FingerprintSHA256: "emu:l0:sha256:0000000000000000000000000000000000000000000000000000000000000000",
				},
				{
					Level:             1,
					Subject:           "CN=DPU Alias Certificate,O=NVIDIA,OU=BlueField-3",
					Issuer:            "CN=DPU Device Identity,O=NVIDIA,OU=BlueField-3",
					NotBefore:         "2024-01-01T00:00:00Z",
					NotAfter:          "2025-01-01T00:00:00Z",
					Algorithm:         "ECDSA-P384",
					PEM:               "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIUEmulatedDICEL1AliasCertificateData0000000wCgYIKoZIzj0E\nAwMwRTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBk5WSURJQTElMCMGA1UEAwwcRFBV\nIERldmljZSBJZGVudGl0eSAoRW11bGF0ZWQpMB4XDTI0MDEwMTAwMDAwMFoXDTI1\nMDEwMTAwMDAwMFowQjELMAkGA1UEBhMCVVMxDzANBgNVBAoMBk5WSURJQTEiMCAG\nA1UEAwwZRFBVIEFsaWFzIENlcnRpZmljYXRlIChFbXUpMHYwEAYHKoZIzj0CAQYF\nK4EEACIDYgAEEmulatedAliasPublicKeyData000000000000000000000000000\nwCgYIKoZIzj0EAwMDaAAwZQIwEmulatedAliasSignatureData00000000000000\n-----END CERTIFICATE-----",
					FingerprintSHA256: "emu:l1:sha256:1111111111111111111111111111111111111111111111111111111111111111",
				},
			},
			Measurements: map[string]string{
				"boot_hash":     "sha384:emulated0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"firmware_hash": "sha384:emulated1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
				"config_hash":   "sha384:emulated2222222222222222222222222222222222222222222222222222222222222222222222222222222222222222",
			},
		},
		Health: &HealthData{
			Healthy:       true,
			Version:       "dpuemu-0.2.0",
			UptimeSeconds: 0,
			Components: map[string]*ComponentHealthData{
				"emulator": {
					Healthy: true,
					Message: "Emulator running with default fixture",
				},
			},
		},
		Metadata: map[string]string{
			"source":      "default",
			"description": "Auto-generated default fixture for local development",
		},
	}
}
