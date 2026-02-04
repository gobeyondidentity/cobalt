package authz

import "github.com/cedar-policy/cedar-go"

// TenantRole represents an operator's membership in a tenant with their role.
// Used for constructing Cedar entities from domain data.
type TenantRole struct {
	TenantID string
	Role     Role
}

// NewOperatorEntity constructs a Cedar entity for an Operator.
// The operator's tenant memberships determine their Parents (tenant hierarchy).
// Attributes include their highest role across all tenants.
//
// For multi-tenant operators, Parents includes all tenant UIDs they belong to.
// The role attribute is set to the highest role (super:admin > tenant:admin > operator).
func NewOperatorEntity(operatorID string, tenants []TenantRole) cedar.Entity {
	operatorUID := cedar.NewEntityUID("Operator", cedar.String(operatorID))

	// Build Parents from tenant memberships
	var parents cedar.EntityUIDSet
	if len(tenants) > 0 {
		tenantUIDs := make([]cedar.EntityUID, 0, len(tenants))
		for _, t := range tenants {
			tenantUIDs = append(tenantUIDs, cedar.NewEntityUID("Tenant", cedar.String(t.TenantID)))
		}
		parents = cedar.NewEntityUIDSet(tenantUIDs...)
	} else {
		parents = cedar.NewEntityUIDSet()
	}

	// Build tenant_ids set (used by policies that check membership)
	tenantIDsSet := make([]cedar.Value, 0, len(tenants))
	for _, t := range tenants {
		tenantIDsSet = append(tenantIDsSet, cedar.String(t.TenantID))
	}

	// Determine highest role across all tenants
	// Role hierarchy: super:admin > tenant:admin > operator
	highestRole := RoleOperator
	for _, t := range tenants {
		if t.Role == RoleSuperAdmin {
			highestRole = RoleSuperAdmin
			break // Can't go higher
		}
		if t.Role == RoleTenantAdmin && highestRole != RoleSuperAdmin {
			highestRole = RoleTenantAdmin
		}
	}

	return cedar.Entity{
		UID:     operatorUID,
		Parents: parents,
		Attributes: cedar.NewRecord(cedar.RecordMap{
			"role":       cedar.String(string(highestRole)),
			"tenant_ids": cedar.NewSet(tenantIDsSet...),
		}),
	}
}

// NewDPUEntity constructs a Cedar entity for a DPU.
// The DPU's tenant determines its Parent (single tenant membership).
// Attributes include attestation_status for policy evaluation.
func NewDPUEntity(dpuID string, tenantID string, attestationStatus AttestationStatus) cedar.Entity {
	dpuUID := cedar.NewEntityUID("DPU", cedar.String(dpuID))

	// DPU belongs to single tenant
	var parents cedar.EntityUIDSet
	if tenantID != "" {
		parents = cedar.NewEntityUIDSet(cedar.NewEntityUID("Tenant", cedar.String(tenantID)))
	} else {
		parents = cedar.NewEntityUIDSet()
	}

	return cedar.Entity{
		UID:     dpuUID,
		Parents: parents,
		Attributes: cedar.NewRecord(cedar.RecordMap{
			"tenant":             cedar.String(tenantID),
			"attestation_status": cedar.String(string(attestationStatus)),
		}),
	}
}

// NewTenantEntity constructs a Cedar entity for a Tenant.
// Tenants are top-level containers with no parents.
func NewTenantEntity(tenantID string, tenantName string) cedar.Entity {
	tenantUID := cedar.NewEntityUID("Tenant", cedar.String(tenantID))

	return cedar.Entity{
		UID:     tenantUID,
		Parents: cedar.NewEntityUIDSet(), // Top-level, no parents
		Attributes: cedar.NewRecord(cedar.RecordMap{
			"name": cedar.String(tenantName),
		}),
	}
}

// NewResourceEntity constructs a generic Cedar entity for any resource type.
// Use this for resources like CertificateAuthority, Authorization, etc.
// The tenantID establishes the resource's Parent relationship.
func NewResourceEntity(resourceType string, resourceID string, tenantID string) cedar.Entity {
	resourceUID := cedar.NewEntityUID(cedar.EntityType(resourceType), cedar.String(resourceID))

	var parents cedar.EntityUIDSet
	if tenantID != "" {
		parents = cedar.NewEntityUIDSet(cedar.NewEntityUID("Tenant", cedar.String(tenantID)))
	} else {
		parents = cedar.NewEntityUIDSet()
	}

	return cedar.Entity{
		UID:     resourceUID,
		Parents: parents,
		Attributes: cedar.NewRecord(cedar.RecordMap{
			"tenant": cedar.String(tenantID),
		}),
	}
}

// buildEntities constructs the Cedar EntityMap from principal and resource.
// This creates the entity graph that Cedar uses to evaluate policies.
func buildEntities(principal Principal, resource Resource) cedar.EntityMap {
	entities := cedar.EntityMap{}

	// Build principal entity
	principalUID := cedar.NewEntityUID(cedar.EntityType(principal.Type), cedar.String(principal.UID))

	// Build tenant parents for principal (supports multi-tenant operators)
	var principalParents cedar.EntityUIDSet
	if len(principal.TenantIDs) > 0 {
		tenantUIDs := make([]cedar.EntityUID, 0, len(principal.TenantIDs))
		for _, tid := range principal.TenantIDs {
			tenantUID := cedar.NewEntityUID("Tenant", cedar.String(tid))
			tenantUIDs = append(tenantUIDs, tenantUID)
			// Ensure tenant entity exists in the map
			if _, exists := entities[tenantUID]; !exists {
				entities[tenantUID] = cedar.Entity{
					UID:        tenantUID,
					Parents:    cedar.NewEntityUIDSet(),
					Attributes: cedar.NewRecord(cedar.RecordMap{}),
				}
			}
		}
		principalParents = cedar.NewEntityUIDSet(tenantUIDs...)
	} else {
		principalParents = cedar.NewEntityUIDSet()
	}

	// Build tenant_ids set for the principal (used by tenant:admin policies)
	tenantIDsSet := make([]cedar.Value, 0, len(principal.TenantIDs))
	for _, tid := range principal.TenantIDs {
		tenantIDsSet = append(tenantIDsSet, cedar.String(tid))
	}

	entities[principalUID] = cedar.Entity{
		UID:     principalUID,
		Parents: principalParents,
		Attributes: cedar.NewRecord(cedar.RecordMap{
			"role":       cedar.String(string(principal.Role)),
			"tenant_ids": cedar.NewSet(tenantIDsSet...),
		}),
	}

	// Build resource entity
	resourceUID := cedar.NewEntityUID(cedar.EntityType(resource.Type), cedar.String(resource.UID))

	var resourceParents cedar.EntityUIDSet
	if resource.TenantID != "" {
		tenantUID := cedar.NewEntityUID("Tenant", cedar.String(resource.TenantID))
		resourceParents = cedar.NewEntityUIDSet(tenantUID)
		// Ensure tenant entity exists in the map
		if _, exists := entities[tenantUID]; !exists {
			entities[tenantUID] = cedar.Entity{
				UID:        tenantUID,
				Parents:    cedar.NewEntityUIDSet(),
				Attributes: cedar.NewRecord(cedar.RecordMap{}),
			}
		}
	} else {
		resourceParents = cedar.NewEntityUIDSet()
	}

	entities[resourceUID] = cedar.Entity{
		UID:     resourceUID,
		Parents: resourceParents,
		Attributes: cedar.NewRecord(cedar.RecordMap{
			"tenant": cedar.String(resource.TenantID),
		}),
	}

	return entities
}

// buildCedarRequest constructs the Cedar request from an AuthzRequest.
// This maps the application-level request to Cedar's evaluation format.
func buildCedarRequest(req AuthzRequest) cedar.Request {
	// Build context record from the request context map
	contextMap := cedar.RecordMap{}

	// Add attestation status if present
	if status, ok := req.Context["attestation_status"].(AttestationStatus); ok {
		contextMap["attestation_status"] = cedar.String(string(status))
	} else if statusStr, ok := req.Context["attestation_status"].(string); ok {
		contextMap["attestation_status"] = cedar.String(statusStr)
	}

	// Add operator_authorized if present (for authorization-based access)
	if authorized, ok := req.Context["operator_authorized"].(bool); ok {
		contextMap["operator_authorized"] = cedar.Boolean(authorized)
	}

	// Add force_bypass_requested if present
	if bypass, ok := req.Context["force_bypass_requested"].(bool); ok {
		contextMap["force_bypass_requested"] = cedar.Boolean(bypass)
	}

	return cedar.Request{
		Principal: cedar.NewEntityUID(cedar.EntityType(req.Principal.Type), cedar.String(req.Principal.UID)),
		Action:    cedar.NewEntityUID("Action", cedar.String(req.Action)),
		Resource:  cedar.NewEntityUID(cedar.EntityType(req.Resource.Type), cedar.String(req.Resource.UID)),
		Context:   cedar.NewRecord(contextMap),
	}
}
