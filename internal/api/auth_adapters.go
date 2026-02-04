package api

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/gobeyondidentity/cobalt/pkg/dpop"
	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// StoreProofValidator adapts the dpop.Validator to the dpop.ProofValidator interface
// by providing a KeyLookup function that queries the store for public keys by kid prefix.
type StoreProofValidator struct {
	validator *dpop.Validator
	store     *store.Store
}

// NewStoreProofValidator creates a new StoreProofValidator.
func NewStoreProofValidator(validator *dpop.Validator, s *store.Store) *StoreProofValidator {
	return &StoreProofValidator{
		validator: validator,
		store:     s,
	}
}

// Validate implements dpop.ProofValidator by adapting the dpop.Validator.
// It provides a KeyLookup function that queries the store based on kid prefix.
func (v *StoreProofValidator) Validate(proof, method, uri string) dpop.ProofValidationResult {
	// Create a key lookup function that queries the store
	keyLookup := func(kid string) ed25519.PublicKey {
		return v.lookupPublicKey(kid)
	}

	// Call the underlying validator
	kidResult, err := v.validator.ValidateProof(proof, method, uri, keyLookup)
	if err != nil {
		// Extract error code from DPoPError if possible
		code := dpop.ErrorCode(err)
		if code == "" {
			code = "dpop.invalid_proof"
		}
		return dpop.ProofValidationResult{
			Valid: false,
			Code:  code,
			Error: err.Error(),
		}
	}

	// Extract JTI from the proof for replay detection
	// The validator already validated the proof, so we can parse it safely
	jti := extractJTI(proof)

	return dpop.ProofValidationResult{
		Valid: true,
		KID:   kidResult,
		JTI:   jti,
	}
}

// lookupPublicKey queries the store for a public key based on kid prefix.
// Returns nil if the key is not found.
func (v *StoreProofValidator) lookupPublicKey(kid string) ed25519.PublicKey {
	switch {
	case strings.HasPrefix(kid, "km_"):
		// KeyMaker lookup
		km, err := v.store.GetKeyMakerByKid(kid)
		if err != nil || km == nil {
			return nil
		}
		// Decode base64-encoded public key
		pubBytes, err := base64.StdEncoding.DecodeString(km.PublicKey)
		if err != nil || len(pubBytes) != ed25519.PublicKeySize {
			return nil
		}
		return ed25519.PublicKey(pubBytes)

	case strings.HasPrefix(kid, "adm_"):
		// Admin key lookup
		ak, err := v.store.GetAdminKeyByKid(kid)
		if err != nil || ak == nil {
			return nil
		}
		// Admin keys store public key as []byte directly
		if len(ak.PublicKey) != ed25519.PublicKeySize {
			return nil
		}
		return ed25519.PublicKey(ak.PublicKey)

	case strings.HasPrefix(kid, "dpu_"):
		// DPU lookup
		dpu, err := v.store.GetDPUByKid(kid)
		if err != nil || dpu == nil {
			return nil
		}
		// DPU stores public key as []byte
		if len(dpu.PublicKey) != ed25519.PublicKeySize {
			return nil
		}
		return ed25519.PublicKey(dpu.PublicKey)

	default:
		// Unknown prefix
		return nil
	}
}

// extractJTI extracts the jti claim from a DPoP proof.
// The proof has already been validated, so we just need to extract the claim.
func extractJTI(proof string) string {
	// Split the JWT into parts
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return ""
	}

	// Decode the payload (second part)
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}

	// Parse as JSON to extract jti claim
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return ""
	}
	return claims.JTI
}

// StoreIdentityLookup implements dpop.IdentityLookup by querying the store.
type StoreIdentityLookup struct {
	store *store.Store
}

// NewStoreIdentityLookup creates a new StoreIdentityLookup.
func NewStoreIdentityLookup(s *store.Store) *StoreIdentityLookup {
	return &StoreIdentityLookup{store: s}
}

// LookupByKID looks up an identity by its kid.
// Returns nil if the kid is not found.
func (l *StoreIdentityLookup) LookupByKID(ctx context.Context, kid string) (*dpop.Identity, error) {
	switch {
	case strings.HasPrefix(kid, "km_"):
		return l.lookupKeyMaker(kid)

	case strings.HasPrefix(kid, "adm_"):
		return l.lookupAdminKey(kid)

	case strings.HasPrefix(kid, "dpu_"):
		return l.lookupDPU(kid)

	default:
		// Unknown prefix, return nil (not found)
		return nil, nil
	}
}

// lookupKeyMaker retrieves identity information for a keymaker.
func (l *StoreIdentityLookup) lookupKeyMaker(kid string) (*dpop.Identity, error) {
	km, err := l.store.GetKeyMakerByKid(kid)
	if err != nil {
		// Check if it's a "not found" error
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "no rows") {
			return nil, nil
		}
		return nil, err
	}
	if km == nil {
		return nil, nil
	}

	return &dpop.Identity{
		KID:        km.Kid,
		CallerType: dpop.CallerTypeKeyMaker,
		Status:     mapKeyMakerStatus(km.Status),
		OperatorID: km.OperatorID,
	}, nil
}

// lookupAdminKey retrieves identity information for an admin key.
func (l *StoreIdentityLookup) lookupAdminKey(kid string) (*dpop.Identity, error) {
	ak, err := l.store.GetAdminKeyByKid(kid)
	if err != nil {
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "no rows") {
			return nil, nil
		}
		return nil, err
	}
	if ak == nil {
		return nil, nil
	}

	return &dpop.Identity{
		KID:        ak.Kid,
		CallerType: dpop.CallerTypeAdmin,
		Status:     mapAdminKeyStatus(ak.Status),
		OperatorID: ak.OperatorID,
	}, nil
}

// lookupDPU retrieves identity information for a DPU.
func (l *StoreIdentityLookup) lookupDPU(kid string) (*dpop.Identity, error) {
	dpu, err := l.store.GetDPUByKid(kid)
	if err != nil {
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "no rows") {
			return nil, nil
		}
		return nil, err
	}
	if dpu == nil {
		return nil, nil
	}

	var tenantID string
	if dpu.TenantID != nil {
		tenantID = *dpu.TenantID
	}

	return &dpop.Identity{
		KID:        *dpu.Kid,
		CallerType: dpop.CallerTypeDPU,
		Status:     mapDPUStatus(dpu.Status),
		TenantID:   tenantID,
	}, nil
}

// mapKeyMakerStatus maps store keymaker status to dpop.IdentityStatus.
func mapKeyMakerStatus(status string) dpop.IdentityStatus {
	switch status {
	case "active":
		return dpop.IdentityStatusActive
	case "suspended":
		return dpop.IdentityStatusSuspended
	case "revoked":
		return dpop.IdentityStatusRevoked
	default:
		// Unknown status defaults to revoked for safety
		return dpop.IdentityStatusRevoked
	}
}

// mapAdminKeyStatus maps store admin key status to dpop.IdentityStatus.
func mapAdminKeyStatus(status string) dpop.IdentityStatus {
	switch status {
	case "active":
		return dpop.IdentityStatusActive
	case "suspended":
		return dpop.IdentityStatusSuspended
	case "revoked":
		return dpop.IdentityStatusRevoked
	default:
		return dpop.IdentityStatusRevoked
	}
}

// mapDPUStatus maps store DPU status to dpop.IdentityStatus.
func mapDPUStatus(status string) dpop.IdentityStatus {
	switch status {
	case "healthy", "enrolled", "active":
		return dpop.IdentityStatusActive
	case "suspended":
		return dpop.IdentityStatusSuspended
	case "revoked":
		return dpop.IdentityStatusRevoked
	case "decommissioned":
		return dpop.IdentityStatusDecommissioned
	default:
		// Unknown DPU status defaults to revoked (deny by default)
		return dpop.IdentityStatusRevoked
	}
}
