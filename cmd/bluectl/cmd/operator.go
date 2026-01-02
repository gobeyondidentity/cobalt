package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nmelo/secure-infra/pkg/store"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(operatorCmd)
	operatorCmd.AddCommand(operatorInviteCmd)
	operatorCmd.AddCommand(operatorListCmd)
	operatorCmd.AddCommand(operatorSuspendCmd)
	operatorCmd.AddCommand(operatorActivateCmd)
	operatorCmd.AddCommand(operatorGrantCmd)
	operatorCmd.AddCommand(operatorAuthorizationsCmd)
	operatorCmd.AddCommand(operatorRevokeCmd)

	// Flags for operator invite
	operatorInviteCmd.Flags().String("role", "operator", "Role: admin or operator")

	// Flags for operator list
	operatorListCmd.Flags().String("tenant", "", "Filter by tenant")


	// Flags for operator revoke
	operatorRevokeCmd.Flags().String("tenant", "", "Tenant name (required)")
	operatorRevokeCmd.Flags().String("ca", "", "CA name to revoke access from (required)")
	operatorRevokeCmd.MarkFlagRequired("tenant")
	operatorRevokeCmd.MarkFlagRequired("ca")
}

var operatorCmd = &cobra.Command{
	Use:   "operator",
	Short: "Manage operators who distribute credentials",
	Long: `Operators are authorized users who can distribute credentials to DPUs.

Admins invite operators to tenants using 'bluectl operator invite'. Operators
then bind their workstation using the 'km' CLI ('km init'), which creates a
hardware-bound credential. Once bound, operators can use 'km' to create SSH CAs
and distribute them to DPUs.

Workflow:
  1. Admin invites operator:     bluectl operator invite user@example.com tenant-name
  2. Operator binds workstation: km init (enter invite code)
  3. Admin grants CA access:     bluectl operator grant user@example.com tenant-name ca-name devices
  4. Operator distributes creds: km distribute ssh-ca ca-name target-dpu`,
}

var operatorInviteCmd = &cobra.Command{
	Use:   "invite <email> <tenant>",
	Short: "Invite an operator to a tenant",
	Long: `Generate an invite code for an operator to join a tenant.

The invite code should be shared with the operator, who will use it
with 'km init' to bind their KeyMaker to the control plane.

Examples:
  bluectl operator invite nelson@acme.com acme
  bluectl operator invite marcus@acme.com acme --role admin`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		tenantName := args[1]
		role, _ := cmd.Flags().GetString("role")

		// Validate role
		if role != "admin" && role != "operator" {
			return fmt.Errorf("invalid role: %s (must be 'admin' or 'operator')", role)
		}

		// Get tenant
		tenant, err := dpuStore.GetTenant(tenantName)
		if err != nil {
			return fmt.Errorf("tenant not found: %s", tenantName)
		}

		// Check if operator exists, create if not
		op, err := dpuStore.GetOperatorByEmail(email)
		if err != nil {
			// Create new operator with pending status
			opID := "op_" + uuid.New().String()[:8]
			if err := dpuStore.CreateOperator(opID, email, ""); err != nil {
				return fmt.Errorf("failed to create operator: %w", err)
			}
			op, _ = dpuStore.GetOperator(opID)
		}

		// Add operator to tenant if not already a member
		_, existingRoleErr := dpuStore.GetOperatorRole(op.ID, tenant.ID)
		if existingRoleErr != nil {
			// Not a member yet, add them
			if err := dpuStore.AddOperatorToTenant(op.ID, tenant.ID, role); err != nil {
				// Ignore duplicate key errors
				if !strings.Contains(err.Error(), "UNIQUE constraint") {
					return fmt.Errorf("failed to add operator to tenant: %w", err)
				}
			}
		}

		// Generate invite code
		prefix := tenant.Name
		if len(prefix) > 4 {
			prefix = prefix[:4]
		}
		code := store.GenerateInviteCode(strings.ToUpper(prefix))

		// Store invite (hashed)
		invite := &store.InviteCode{
			ID:            "inv_" + uuid.New().String()[:8],
			CodeHash:      store.HashInviteCode(code),
			OperatorEmail: email,
			TenantID:      tenant.ID,
			Role:          role,
			CreatedBy:     "admin", // TODO: get from auth context
			ExpiresAt:     time.Now().Add(24 * time.Hour),
			Status:        "pending",
		}

		if err := dpuStore.CreateInviteCode(invite); err != nil {
			return fmt.Errorf("failed to create invite: %w", err)
		}

		fmt.Printf("Invite created for %s\n", email)
		fmt.Printf("Code: %s\n", code)
		fmt.Printf("Expires: %s\n", invite.ExpiresAt.Format(time.RFC3339))
		fmt.Println()
		fmt.Println("Share this code with the operator. They will run:")
		fmt.Printf("  km init\n")

		return nil
	},
}

var operatorListCmd = &cobra.Command{
	Use:   "list",
	Short: "List operators",
	Long: `List all operators, optionally filtered by tenant.

Examples:
  bluectl operator list
  bluectl operator list --tenant acme`,
	RunE: func(cmd *cobra.Command, args []string) error {
		tenantFilter, _ := cmd.Flags().GetString("tenant")

		var operators []*store.Operator
		var err error

		if tenantFilter != "" {
			tenant, err := dpuStore.GetTenant(tenantFilter)
			if err != nil {
				return fmt.Errorf("tenant not found: %s", tenantFilter)
			}
			operators, err = dpuStore.ListOperatorsByTenant(tenant.ID)
			if err != nil {
				return err
			}
		} else {
			operators, err = dpuStore.ListOperators()
			if err != nil {
				return err
			}
		}

		if outputFormat != "table" {
			return formatOutput(operators)
		}

		if len(operators) == 0 {
			fmt.Println("No operators found.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "EMAIL\tSTATUS\tCREATED")
		for _, op := range operators {
			fmt.Fprintf(w, "%s\t%s\t%s\n",
				op.Email, op.Status, op.CreatedAt.Format("2006-01-02"))
		}
		w.Flush()
		return nil
	},
}

var operatorSuspendCmd = &cobra.Command{
	Use:   "suspend <email>",
	Short: "Suspend an operator",
	Long: `Suspend an operator. Their KeyMakers remain bound but all
authorization checks will fail until reactivated.

Examples:
  bluectl operator suspend marcus@acme.com`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]

		op, err := dpuStore.GetOperatorByEmail(email)
		if err != nil {
			return fmt.Errorf("operator not found: %s", email)
		}

		if op.Status == "suspended" {
			fmt.Printf("Operator %s is already suspended.\n", email)
			return nil
		}

		if err := dpuStore.UpdateOperatorStatus(op.ID, "suspended"); err != nil {
			return err
		}

		fmt.Printf("Operator %s suspended.\n", email)
		return nil
	},
}

var operatorActivateCmd = &cobra.Command{
	Use:   "activate <email>",
	Short: "Activate a suspended operator",
	Long: `Activate an operator who was previously suspended or pending.

Examples:
  bluectl operator activate marcus@acme.com`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]

		op, err := dpuStore.GetOperatorByEmail(email)
		if err != nil {
			return fmt.Errorf("operator not found: %s", email)
		}

		if op.Status == "active" {
			fmt.Printf("Operator %s is already active.\n", email)
			return nil
		}

		if err := dpuStore.UpdateOperatorStatus(op.ID, "active"); err != nil {
			return err
		}

		fmt.Printf("Operator %s activated.\n", email)
		return nil
	},
}

var operatorGrantCmd = &cobra.Command{
	Use:   "grant <email> <tenant> <ca> <devices>",
	Short: "Grant authorization to an operator",
	Long: `Grant an operator access to a CA and set of devices within a tenant.

Arguments:
  email    Operator email address
  tenant   Tenant name
  ca       CA name to grant access to
  devices  Device selector: comma-separated names or 'all'

Examples:
  bluectl operator grant nelson@acme.com acme ops-ca bf3-lab-01
  bluectl operator grant nelson@acme.com acme ops-ca bf3-lab-01,bf3-lab-02
  bluectl operator grant nelson@acme.com acme dev-ca all`,
	Args: cobra.ExactArgs(4),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		tenantName := args[1]
		caName := args[2]
		devicesArg := args[3]

		// Look up operator by email
		op, err := dpuStore.GetOperatorByEmail(email)
		if err != nil {
			return fmt.Errorf("operator '%s' not found", email)
		}

		// Look up tenant by name
		tenant, err := dpuStore.GetTenant(tenantName)
		if err != nil {
			return fmt.Errorf("tenant '%s' not found", tenantName)
		}

		// Look up CA by name and verify it belongs to this tenant
		ca, err := dpuStore.GetSSHCA(caName)
		if err != nil {
			return fmt.Errorf("CA '%s' not found in tenant '%s'", caName, tenantName)
		}
		// Verify CA belongs to tenant (if tenant-scoped)
		if ca.TenantID != nil && *ca.TenantID != tenant.ID {
			return fmt.Errorf("CA '%s' not found in tenant '%s'", caName, tenantName)
		}

		// Parse device selector
		var deviceIDs []string
		var deviceNames []string
		if strings.ToLower(devicesArg) == "all" {
			deviceIDs = []string{"all"}
			deviceNames = []string{"all"}
		} else {
			// Split on comma and validate each device exists
			names := strings.Split(devicesArg, ",")
			for _, name := range names {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				// Look up device (DPU) by name
				dpu, err := dpuStore.Get(name)
				if err != nil {
					return fmt.Errorf("device '%s' not found", name)
				}
				deviceIDs = append(deviceIDs, dpu.ID)
				deviceNames = append(deviceNames, dpu.Name)
			}
		}

		// Create authorization
		authID := "auth_" + uuid.New().String()[:8]
		err = dpuStore.CreateAuthorization(
			authID,
			op.ID,
			tenant.ID,
			[]string{ca.ID},
			deviceIDs,
			"admin", // TODO: get from auth context in Phase 3
			nil,     // no expiration
		)
		if err != nil {
			return fmt.Errorf("failed to create authorization: %w", err)
		}

		fmt.Println("Authorization granted:")
		fmt.Printf("  Operator: %s\n", email)
		fmt.Printf("  Tenant:   %s\n", tenantName)
		fmt.Printf("  CA:       %s\n", caName)
		fmt.Printf("  Devices:  %s\n", strings.Join(deviceNames, ", "))
		return nil
	},
}

var operatorAuthorizationsCmd = &cobra.Command{
	Use:   "authorizations <email>",
	Short: "List operator's authorizations",
	Long: `List all authorizations granted to an operator.

Examples:
  bluectl operator authorizations nelson@acme.com`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]

		// Look up operator by email
		op, err := dpuStore.GetOperatorByEmail(email)
		if err != nil {
			return fmt.Errorf("operator '%s' not found", email)
		}

		// List authorizations for this operator
		auths, err := dpuStore.ListAuthorizationsByOperator(op.ID)
		if err != nil {
			return fmt.Errorf("failed to list authorizations: %w", err)
		}

		if len(auths) == 0 {
			fmt.Printf("No authorizations found for %s.\n", email)
			return nil
		}

		// Build a lookup map for tenants and CAs
		tenants := make(map[string]string) // ID -> name
		cas := make(map[string]string)     // ID -> name
		devices := make(map[string]string) // ID -> name

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TENANT\tCA\tDEVICES\tEXPIRES")

		for _, auth := range auths {
			// Get tenant name (cache lookup)
			tenantName := tenants[auth.TenantID]
			if tenantName == "" {
				if t, err := dpuStore.GetTenant(auth.TenantID); err == nil {
					tenantName = t.Name
					tenants[auth.TenantID] = tenantName
				} else {
					tenantName = auth.TenantID
				}
			}

			// Get CA names
			var caNames []string
			for _, caID := range auth.CAIDs {
				caName := cas[caID]
				if caName == "" {
					if c, err := dpuStore.GetSSHCAByID(caID); err == nil {
						caName = c.Name
						cas[caID] = caName
					} else {
						caName = caID
					}
				}
				caNames = append(caNames, caName)
			}

			// Get device names
			var deviceNames []string
			for _, deviceID := range auth.DeviceIDs {
				if deviceID == "all" {
					deviceNames = append(deviceNames, "all")
					continue
				}
				deviceName := devices[deviceID]
				if deviceName == "" {
					if d, err := dpuStore.Get(deviceID); err == nil {
						deviceName = d.Name
						devices[deviceID] = deviceName
					} else {
						deviceName = deviceID
					}
				}
				deviceNames = append(deviceNames, deviceName)
			}

			// Format expiration
			expires := "never"
			if auth.ExpiresAt != nil {
				expires = auth.ExpiresAt.Format("2006-01-02")
			}

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				tenantName,
				strings.Join(caNames, ", "),
				strings.Join(deviceNames, ", "),
				expires)
		}
		w.Flush()
		return nil
	},
}

var operatorRevokeCmd = &cobra.Command{
	Use:   "revoke <email>",
	Short: "Revoke specific authorization",
	Long: `Revoke an operator's authorization for a specific CA within a tenant.

Examples:
  bluectl operator revoke nelson@acme.com --tenant acme --ca ops-ca`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		tenantName, _ := cmd.Flags().GetString("tenant")
		caName, _ := cmd.Flags().GetString("ca")

		// Look up operator by email
		op, err := dpuStore.GetOperatorByEmail(email)
		if err != nil {
			return fmt.Errorf("operator '%s' not found", email)
		}

		// Look up tenant by name
		tenant, err := dpuStore.GetTenant(tenantName)
		if err != nil {
			return fmt.Errorf("tenant '%s' not found", tenantName)
		}

		// Look up CA by name
		ca, err := dpuStore.GetSSHCA(caName)
		if err != nil {
			return fmt.Errorf("CA '%s' not found in tenant '%s'", caName, tenantName)
		}

		// Find authorization matching operator + tenant + CA
		auths, err := dpuStore.ListAuthorizationsByOperator(op.ID)
		if err != nil {
			return fmt.Errorf("failed to list authorizations: %w", err)
		}

		var authToDelete *store.Authorization
		for _, auth := range auths {
			if auth.TenantID != tenant.ID {
				continue
			}
			// Check if this authorization includes the specified CA
			for _, caID := range auth.CAIDs {
				if caID == ca.ID {
					authToDelete = auth
					break
				}
			}
			if authToDelete != nil {
				break
			}
		}

		if authToDelete == nil {
			return fmt.Errorf("no authorization found for operator '%s' on CA '%s'", email, caName)
		}

		// Delete the authorization
		if err := dpuStore.DeleteAuthorization(authToDelete.ID); err != nil {
			return fmt.Errorf("failed to revoke authorization: %w", err)
		}

		fmt.Println("Authorization revoked:")
		fmt.Printf("  Operator: %s\n", email)
		fmt.Printf("  CA:       %s\n", caName)
		return nil
	},
}
