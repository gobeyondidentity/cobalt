// Package dpop implements DPoP (Demonstrating Proof of Possession) tokens
// per RFC 9449.
//
// DPoP binds access tokens to a specific client key pair, preventing token
// theft and replay attacks. All API authentication in Secure Infrastructure
// uses DPoP with Ed25519 keys.
//
// # Token Structure
//
// A DPoP proof is a JWT containing:
//   - jti: Unique token identifier
//   - htm: HTTP method (GET, POST, etc.)
//   - htu: HTTP URI being accessed
//   - iat: Issued-at timestamp
//   - jwk: Public key in JWK format (header)
//
// # Usage
//
// Create proofs for API requests:
//
//	signer := dpop.NewSigner(privateKey)
//	proof, err := signer.CreateProof("POST", "https://nexus/api/v1/enroll")
//
// Verify incoming proofs:
//
//	verifier := dpop.NewVerifier()
//	claims, err := verifier.Verify(proofToken, "POST", "https://nexus/api/v1/enroll")
package dpop
