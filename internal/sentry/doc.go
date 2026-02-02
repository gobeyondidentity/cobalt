// Package sentry implements the Host Agent that runs on servers with
// BlueField DPUs installed.
//
// Sentry bridges the control plane (nexus) and the DPU agent (aegis).
// It receives credentials from nexus and delivers them to applications
// on the host, with delivery gated by attestation status from aegis.
//
// # Responsibilities
//
//   - Receive credentials pushed from nexus
//   - Query aegis for current attestation status
//   - Write credentials to configured paths when attestation passes
//   - Expose gRPC API for local applications to query credential status
//
// # Communication
//
// Sentry communicates with aegis over the PCIe bus using the transport
// package (DOCA ComCh or tmfifo_net). It communicates with nexus over
// HTTPS with DPoP authentication.
//
// # Configuration
//
// Sentry reads configuration from /etc/sentry/config.yaml specifying
// the nexus endpoint, credential output paths, and transport options.
package sentry
