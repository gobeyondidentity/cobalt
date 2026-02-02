// Package api implements the HTTP API server for the Secure Infrastructure
// control plane (nexus).
//
// The API serves three client types:
//
//   - Operators (keymaker): Credential management via DPoP-authenticated requests
//   - Administrators (bluectl): System configuration and monitoring
//   - DPU agents (aegis): Enrollment, attestation, and credential retrieval
//
// # Authentication
//
// All endpoints require DPoP proof tokens (RFC 9449) bound to Ed25519 keys.
// There are no bearer tokens or session cookies.
//
// # Endpoints
//
// Bootstrap and enrollment:
//   - POST /api/v1/bootstrap - Initial server setup
//   - POST /api/v1/enroll - DPU enrollment with invite code
//   - POST /api/v1/enroll/challenge - Enrollment challenge-response
//
// Credential management:
//   - POST /api/v1/credentials - Create credential for distribution
//   - GET /api/v1/credentials/pending - Poll for queued credentials
//
// Trust and attestation:
//   - POST /api/v1/trust/rim - Upload reference integrity manifest
//   - POST /api/v1/attest - Submit attestation evidence
//
// # Error Handling
//
// Errors return RFC 7807 problem details with appropriate HTTP status codes.
// Internal errors are logged but not exposed to clients.
package api
