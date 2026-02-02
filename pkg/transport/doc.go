// Package transport provides communication abstractions for Host-DPU messaging.
//
// The transport layer enables bidirectional communication between the host
// agent (sentry) and the DPU agent (aegis) over the PCIe bus.
//
// # Transport Implementations
//
// Two transports are available:
//
//   - DOCA ComCh: Native NVIDIA communication channel using DOCA SDK.
//     Requires DOCA libraries and BlueField hardware. Used in production.
//
//   - tmfifo_net: TCP over the virtual ethernet interface (192.168.100.0/30).
//     Works on any BlueField but has lower throughput. Used as fallback.
//
// # Protocol
//
// Messages use a simple framing protocol with type, length, and payload.
// See [Message] for the wire format. The transport handles framing,
// retries, and connection management.
//
// # Usage
//
// Aegis (DPU side) listens for connections:
//
//	listener, err := transport.Listen(ctx, opts)
//	conn, err := listener.Accept()
//
// Sentry (host side) connects:
//
//	conn, err := transport.Dial(ctx, opts)
//
// Both sides then exchange messages:
//
//	err := conn.Send(msg)
//	msg, err := conn.Recv()
package transport
