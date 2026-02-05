// Identity store methods have been split into focused files:
//   - operators.go: Operator and OperatorTenant methods
//   - keymakers.go: KeyMaker methods
//   - admin_keys.go: AdminKey methods
//   - invites.go: InviteCode methods
//   - sqlite.go: DPU DPoP lookup methods (GetDPUByKid, GetDPUByFingerprint)
//
// Type definitions remain in sqlite.go.
package store
