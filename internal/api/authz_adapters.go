package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gobeyondidentity/cobalt/pkg/authz"
	"github.com/gobeyondidentity/cobalt/pkg/dpop"
	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// StorePrincipalLookup resolves DPoP identities to authorization principals using the store.
type StorePrincipalLookup struct {
	store *store.Store
}

// NewStorePrincipalLookup creates a principal lookup backed by the store.
func NewStorePrincipalLookup(s *store.Store) *StorePrincipalLookup {
	return &StorePrincipalLookup{store: s}
}

// LookupPrincipal resolves an authenticated identity to a principal with role and tenants.
func (l *StorePrincipalLookup) LookupPrincipal(ctx context.Context, identity *dpop.Identity) (*authz.Principal, error) {
	if identity == nil {
		return nil, fmt.Errorf("identity is nil")
	}

	switch identity.CallerType {
	case dpop.CallerTypeKeyMaker, dpop.CallerTypeAdmin:
		return l.lookupOperatorPrincipal(ctx, identity)
	case dpop.CallerTypeDPU:
		return l.lookupDPUPrincipal(ctx, identity)
	default:
		return nil, fmt.Errorf("unknown caller type: %s", identity.CallerType)
	}
}

// lookupOperatorPrincipal resolves a keymaker or admin identity to a principal.
func (l *StorePrincipalLookup) lookupOperatorPrincipal(ctx context.Context, identity *dpop.Identity) (*authz.Principal, error) {
	operatorID := identity.OperatorID
	if operatorID == "" {
		return nil, fmt.Errorf("operator ID is empty for identity %s", identity.KID)
	}

	// Get tenant memberships and roles
	tenants, err := l.store.GetOperatorTenants(operatorID)
	if err != nil {
		return nil, fmt.Errorf("failed to get operator tenants: %w", err)
	}

	// Determine highest role and collect tenant IDs
	var tenantIDs []string
	highestRole := authz.RoleOperator // Default to lowest role

	for _, t := range tenants {
		tenantIDs = append(tenantIDs, t.TenantID)

		// Map store role to authz role and track highest
		var role authz.Role
		switch t.Role {
		case "super:admin":
			role = authz.RoleSuperAdmin
		case "tenant:admin", "admin":
			role = authz.RoleTenantAdmin
		default:
			role = authz.RoleOperator
		}

		if roleRank(role) > roleRank(highestRole) {
			highestRole = role
		}
	}

	// Check if operator has super:admin in any tenant
	isSuperAdmin, err := l.store.IsSuperAdmin(operatorID)
	if err != nil {
		return nil, fmt.Errorf("failed to check super admin status: %w", err)
	}
	if isSuperAdmin {
		highestRole = authz.RoleSuperAdmin
	}

	return &authz.Principal{
		UID:       identity.KID,
		Type:      authz.PrincipalOperator,
		Role:      highestRole,
		TenantIDs: tenantIDs,
	}, nil
}

// lookupDPUPrincipal resolves a DPU identity to a principal.
func (l *StorePrincipalLookup) lookupDPUPrincipal(ctx context.Context, identity *dpop.Identity) (*authz.Principal, error) {
	var tenantIDs []string
	if identity.TenantID != "" {
		tenantIDs = []string{identity.TenantID}
	}

	return &authz.Principal{
		UID:       identity.KID,
		Type:      authz.PrincipalDPU,
		Role:      authz.RoleOperator, // DPUs don't have admin roles
		TenantIDs: tenantIDs,
	}, nil
}

// roleRank returns a numeric rank for role comparison.
// Higher rank = more permissions.
func roleRank(role authz.Role) int {
	switch role {
	case authz.RoleSuperAdmin:
		return 3
	case authz.RoleTenantAdmin:
		return 2
	case authz.RoleOperator:
		return 1
	default:
		return 0
	}
}

// StoreResourceExtractor extracts resource information from HTTP requests.
type StoreResourceExtractor struct {
	store *store.Store
}

// NewStoreResourceExtractor creates a resource extractor backed by the store.
func NewStoreResourceExtractor(s *store.Store) *StoreResourceExtractor {
	return &StoreResourceExtractor{store: s}
}

// ExtractResource determines the target resource from the request.
func (e *StoreResourceExtractor) ExtractResource(r *http.Request, action authz.Action, principal *authz.Principal) (*authz.Resource, error) {
	// Determine resource type from action
	resourceType := actionToResourceType(string(action))

	// Try to get resource ID from path parameter
	resourceID := r.PathValue("id")

	// Handle self-referential endpoints
	if resourceID == "me" || resourceID == "" {
		if isSelfAction(string(action)) {
			resourceID = principal.UID
		}
	}

	// For POST/PUT, try to extract resource info from body if needed
	if resourceID == "" && (r.Method == "POST" || r.Method == "PUT") {
		bodyID, _ := extractIDFromBody(r)
		if bodyID != "" {
			resourceID = bodyID
		}
	}

	// Get tenant ID for the resource
	tenantID := e.getResourceTenantID(resourceID, resourceType, principal)

	return &authz.Resource{
		UID:      resourceID,
		Type:     resourceType,
		TenantID: tenantID,
	}, nil
}

// actionToResourceType maps Cedar actions to resource types.
func actionToResourceType(action string) string {
	switch {
	case strings.HasPrefix(action, "operator:"):
		return "Operator"
	case strings.HasPrefix(action, "role:"):
		return "Operator"
	case strings.HasPrefix(action, "dpu:"):
		return "DPU"
	case strings.HasPrefix(action, "credential:"):
		return "DPU"
	case strings.HasPrefix(action, "distribution:"):
		return "Distribution"
	case strings.HasPrefix(action, "authorization:"):
		return "Authorization"
	case strings.HasPrefix(action, "tenant:"):
		return "Tenant"
	case strings.HasPrefix(action, "audit:"):
		return "Audit"
	case strings.HasPrefix(action, "trust:"):
		return "TrustRelationship"
	default:
		return "Unknown"
	}
}

// isSelfAction returns true if the action is self-referential.
func isSelfAction(action string) bool {
	return action == authz.ActionOperatorReadSelf || action == authz.ActionDPUReadOwnConfig
}

// extractIDFromBody tries to extract a resource ID from the request body.
// Returns empty string if not found or on error.
// IMPORTANT: This function restores the body so handlers can read it.
func extractIDFromBody(r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}

	// Read body (limit to prevent memory exhaustion)
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return "", err
	}

	// Restore the body for downstream handlers
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Try to parse as JSON
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return "", nil
	}

	// Look for common ID fields
	for _, field := range []string{"id", "dpu_id", "dpuId", "device_id", "operator_id", "tenant_id"} {
		if v, ok := data[field]; ok {
			if s, ok := v.(string); ok {
				return s, nil
			}
		}
	}

	return "", nil
}

// getResourceTenantID determines the tenant ID for a resource.
func (e *StoreResourceExtractor) getResourceTenantID(resourceID, resourceType string, principal *authz.Principal) string {
	// If resource ID is empty, use principal's tenant if they have one
	if resourceID == "" && len(principal.TenantIDs) > 0 {
		return principal.TenantIDs[0]
	}

	// Try to look up resource tenant from store based on type
	if resourceID != "" {
		switch resourceType {
		case "DPU":
			if dpu, err := e.store.Get(resourceID); err == nil && dpu != nil && dpu.TenantID != nil {
				return *dpu.TenantID
			}
		case "Operator":
			// Operators can belong to multiple tenants; use first if available
			if tenants, err := e.store.GetOperatorTenants(resourceID); err == nil && len(tenants) > 0 {
				return tenants[0].TenantID
			}
		}
	}

	// Fall back to principal's first tenant
	if len(principal.TenantIDs) > 0 {
		return principal.TenantIDs[0]
	}

	return ""
}

// StoreAttestationLookup retrieves attestation status from the store.
type StoreAttestationLookup struct {
	store *store.Store
}

// NewStoreAttestationLookup creates an attestation lookup backed by the store.
func NewStoreAttestationLookup(s *store.Store) *StoreAttestationLookup {
	return &StoreAttestationLookup{store: s}
}

// GetAttestationStatus returns the current attestation status for a DPU.
func (l *StoreAttestationLookup) GetAttestationStatus(ctx context.Context, dpuID string) (authz.AttestationStatus, error) {
	// Extract DPU name from ID (strip prefix if present)
	dpuName := dpuID
	if strings.HasPrefix(dpuID, "dpu_") {
		// Need to look up the DPU to get its name
		dpu, err := l.store.Get(dpuID)
		if err != nil || dpu == nil {
			return authz.AttestationUnavailable, nil
		}
		dpuName = dpu.Name
	}

	// Get attestation record
	att, err := l.store.GetAttestation(dpuName)
	if err != nil {
		return authz.AttestationUnavailable, nil
	}
	if att == nil {
		return authz.AttestationUnavailable, nil
	}

	// Map store attestation status to authz attestation status
	switch att.Status {
	case store.AttestationStatusVerified:
		return authz.AttestationVerified, nil
	case store.AttestationStatusStale:
		return authz.AttestationStale, nil
	case store.AttestationStatusFailed:
		return authz.AttestationFailed, nil
	case store.AttestationStatusUnavailable, store.AttestationStatusPending:
		return authz.AttestationUnavailable, nil
	default:
		return authz.AttestationUnavailable, nil
	}
}
