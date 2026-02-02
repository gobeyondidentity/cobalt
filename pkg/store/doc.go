// Package store provides SQLite-based persistence for the Secure Infrastructure
// control plane.
//
// The store manages several domain entities:
//
//   - Identities: DPUs, operators (keymaker), and administrators
//   - Credentials: SSH CA certificates and other secrets queued for delivery
//   - Attestation: DICE/SPDM measurements and trust decisions
//   - Enrollment: Invite codes and session state for device onboarding
//   - Authorization: Cedar policies and evaluation results
//   - Audit: Immutable log of security-relevant events
//
// All data is encrypted at rest using AES-256-GCM with a key derived from
// the server's root secret.
//
// # Usage
//
// Open a store with [Open] and close it when done:
//
//	db, err := store.Open("nexus.db", encryptionKey)
//	if err != nil {
//	    return err
//	}
//	defer db.Close()
//
// # Thread Safety
//
// The store is safe for concurrent use. SQLite WAL mode enables readers and
// writers to operate simultaneously.
package store
