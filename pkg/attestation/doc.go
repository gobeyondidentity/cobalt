// Package attestation provides DICE/SPDM attestation verification for
// BlueField DPUs.
//
// Attestation establishes hardware identity and integrity by verifying
// cryptographic evidence from the DPU's DICE certificate chain and SPDM
// measurements against known-good reference values.
//
// # Components
//
//   - TrustChecker: Validates DICE chains and SPDM measurements
//   - Gate: Enforces attestation requirements before granting access
//   - Refresher: Periodically re-attests enrolled devices
//   - RIM: Reference Integrity Manifest storage and lookup
//
// # Verification Flow
//
//  1. DPU presents DICE certificate chain during enrollment
//  2. TrustChecker validates chain against trusted root
//  3. SPDM measurements are compared to RIM entries
//  4. On success, device gains attested status
//  5. Refresher re-verifies at configured intervals
//
// # Data Sources
//
// Attestation evidence is retrieved via Redfish from the DPU's BMC.
// Reference values come from NVIDIA-signed RIM files uploaded by
// administrators.
package attestation
