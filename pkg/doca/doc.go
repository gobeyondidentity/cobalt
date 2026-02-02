// Package doca provides system information and inventory queries for
// NVIDIA BlueField DPUs.
//
// This package wraps DOCA SDK calls to retrieve hardware details like
// PCI addresses, firmware versions, and device capabilities. It does
// not handle communication; see package transport for that.
//
// # Build Tags
//
// Functions requiring the DOCA SDK are guarded by build tags:
//
//	go build -tags=dpu,doca ./cmd/aegis
//
// On non-DPU systems, stub implementations return appropriate errors.
package doca
