package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

// ValidRoles defines the valid role values for operator invites.
var ValidRoles = []string{"operator", "tenant:admin", "super:admin"}

func init() {
	rootCmd.AddCommand(operatorCmd)
	operatorCmd.AddCommand(operatorInviteCmd)
	operatorCmd.AddCommand(operatorListCmd)
	operatorCmd.AddCommand(operatorSuspendCmd)
	operatorCmd.AddCommand(operatorUnsuspendCmd)
	operatorCmd.AddCommand(operatorGrantCmd)
	operatorCmd.AddCommand(operatorAuthorizationsCmd)
	operatorCmd.AddCommand(operatorRevokeCmd)
	operatorCmd.AddCommand(operatorRemoveCmd)
	operatorCmd.AddCommand(operatorSetRoleCmd)
	operatorCmd.AddCommand(operatorRemoveRoleCmd)

	// No flags for operator invite - role is now a positional argument

	// Flags for operator list
	operatorListCmd.Flags().String("tenant", "", "Filter by tenant")
	operatorListCmd.Flags().String("status", "", "Filter by status (active, suspended)")

	// Flags for operator suspend
	operatorSuspendCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")

	// Flags for operator revoke
	operatorRevokeCmd.Flags().String("tenant", "", "Tenant name (required)")
	operatorRevokeCmd.Flags().String("ca", "", "CA name to revoke access from (required)")
	operatorRevokeCmd.MarkFlagRequired("tenant")
	operatorRevokeCmd.MarkFlagRequired("ca")

	// Flags for operator remove
	operatorRemoveCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")
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
	Use:   "invite <email> <tenant> [role]",
	Short: "Invite an operator to a tenant",
	Long: `Generate an invite code for an operator to join a tenant.

The invite code should be shared with the operator, who will use it
with 'km init' to bind their KeyMaker to the control plane.

Arguments:
  email   Operator email address
  tenant  Tenant name
  role    Role to assign (optional, default: operator)
          Valid values: operator, tenant:admin, super:admin

Examples:
  bluectl operator invite nelson@acme.com acme
  bluectl operator invite marcus@acme.com acme tenant:admin
  bluectl operator invite admin@acme.com acme super:admin`,
	Args: RangeArgsWithUsage(2, 3),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		tenantName := args[1]

		// Default role to "operator" if not provided
		role := "operator"
		if len(args) == 3 {
			role = args[2]
		}

		// Validate role
		validRole := false
		for _, r := range ValidRoles {
			if role == r {
				validRole = true
				break
			}
		}
		if !validRole {
			return fmt.Errorf("invalid role: %s (must be one of: %s)", role, strings.Join(ValidRoles, ", "))
		}

		serverURL, err := requireServer()
		if err != nil {
			return err
		}
		return inviteOperatorRemote(cmd.Context(), serverURL, email, tenantName, role)
	},
}

func inviteOperatorRemote(ctx context.Context, serverURL, email, tenantName, role string) error {
	client, err := NewNexusClientWithDPoP(serverURL)
	if err != nil {
		return err
	}
	resp, err := client.InviteOperator(ctx, email, tenantName, role)
	if err != nil {
		return fmt.Errorf("failed to invite operator on server: %w", err)
	}

	if outputFormat == "json" || outputFormat == "yaml" {
		return formatOutput(resp)
	}

	if resp.Status == "additional_device" {
		fmt.Printf("Invite created for %s (additional device)\n", email)
		fmt.Printf("Code: %s\n", resp.InviteCode)
		fmt.Printf("Expires: %s\n", resp.ExpiresAt)
		fmt.Println()
		fmt.Println("This operator already has active KeyMakers.")
		fmt.Println("Share this code to enroll an additional device:")
		fmt.Println("  1. Run: km init")
		fmt.Println("  2. Enter the invite code when prompted")
		return nil
	}

	fmt.Printf("Invite created for %s\n", email)
	fmt.Printf("Code: %s\n", resp.InviteCode)
	fmt.Printf("Expires: %s\n", resp.ExpiresAt)
	fmt.Println()
	fmt.Println("Share this code with the operator. They will need to:")
	fmt.Println("  1. Run: km init")
	fmt.Println("  2. Enter the invite code when prompted")

	return nil
}

// validOperatorStatuses defines the valid status values for operator list filtering.
var validOperatorStatuses = []string{"active", "suspended"}

var operatorListCmd = &cobra.Command{
	Use:   "list",
	Short: "List operators",
	Long: `List all operators, optionally filtered by tenant and/or status.

Examples:
  bluectl operator list
  bluectl operator list --tenant acme
  bluectl operator list --status suspended
  bluectl operator list --tenant acme --status active`,
	RunE: func(cmd *cobra.Command, args []string) error {
		tenantFilter, _ := cmd.Flags().GetString("tenant")
		statusFilter, _ := cmd.Flags().GetString("status")

		// Validate status if provided
		if statusFilter != "" {
			valid := false
			for _, s := range validOperatorStatuses {
				if statusFilter == s {
					valid = true
					break
				}
			}
			if !valid {
				return fmt.Errorf("invalid status: %s (must be one of: %s)", statusFilter, strings.Join(validOperatorStatuses, ", "))
			}
		}

		serverURL, err := requireServer()
		if err != nil {
			return err
		}
		return listOperatorsRemote(cmd.Context(), serverURL, tenantFilter, statusFilter)
	},
}

func listOperatorsRemote(ctx context.Context, serverURL, tenantFilter, statusFilter string) error {
	client, err := NewNexusClientWithDPoP(serverURL)
	if err != nil {
		return err
	}
	operators, err := client.ListOperators(ctx, tenantFilter, statusFilter)
	if err != nil {
		return fmt.Errorf("failed to list operators: %w", err)
	}

	if outputFormat != "table" {
		if len(operators) == 0 {
			fmt.Println("[]")
			return nil
		}
		return formatOutput(operators)
	}

	if len(operators) == 0 {
		fmt.Println("No operators found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "EMAIL\tTENANT\tROLE\tSTATUS\tCREATED")
	for _, op := range operators {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", op.Email, op.TenantName, op.Role, op.Status, op.CreatedAt)
	}
	w.Flush()
	return nil
}

var operatorSuspendCmd = &cobra.Command{
	Use:   "suspend <email>",
	Short: "Suspend an operator",
	Long: `Suspend an operator. Their KeyMakers remain bound but all
authorization checks will fail until reactivated.

Examples:
  bluectl operator suspend marcus@acme.com
  bluectl operator suspend marcus@acme.com --yes`,
	Args: ExactArgsWithUsage(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		skipConfirm, _ := cmd.Flags().GetBool("yes")

		serverURL, err := requireServer()
		if err != nil {
			return err
		}

		client, err := NewNexusClientWithDPoP(serverURL)
		if err != nil {
			return err
		}

		// Check current status
		op, err := client.GetOperator(cmd.Context(), email)
		if err != nil {
			return fmt.Errorf("operator not found: %s", email)
		}

		if op.Status == "suspended" {
			fmt.Printf("Operator %s is already suspended.\n", email)
			return nil
		}

		if !skipConfirm {
			fmt.Printf("Suspend operator '%s'? Their KeyMakers will be blocked from distributing credentials.\n", email)
			fmt.Print("Type 'yes' to confirm: ")

			reader := bufio.NewReader(os.Stdin)
			response, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read confirmation: %w", err)
			}

			response = strings.TrimSpace(strings.ToLower(response))
			if response != "yes" {
				fmt.Println("Suspension cancelled.")
				return nil
			}
		}

		if err := client.UpdateOperatorStatus(cmd.Context(), email, "suspended"); err != nil {
			return err
		}

		fmt.Printf("Operator %s suspended.\n", email)
		return nil
	},
}

var operatorUnsuspendCmd = &cobra.Command{
	Use:     "unsuspend <email>",
	Aliases: []string{"activate"},
	Short:   "Unsuspend a suspended operator",
	Long: `Unsuspend an operator who was previously suspended.

Examples:
  bluectl operator unsuspend marcus@acme.com`,
	Args: ExactArgsWithUsage(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]

		serverURL, err := requireServer()
		if err != nil {
			return err
		}

		client, err := NewNexusClientWithDPoP(serverURL)
		if err != nil {
			return err
		}

		// Check current status
		op, err := client.GetOperator(cmd.Context(), email)
		if err != nil {
			return fmt.Errorf("operator not found: %s", email)
		}

		if op.Status == "active" {
			fmt.Printf("Operator %s is already active.\n", email)
			return nil
		}

		if err := client.UpdateOperatorStatus(cmd.Context(), email, "active"); err != nil {
			return err
		}

		fmt.Printf("Operator %s unsuspended.\n", email)
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
	Args: ExactArgsWithUsage(4),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		tenantName := args[1]
		caName := args[2]
		devicesArg := args[3]

		serverURL, err := requireServer()
		if err != nil {
			return err
		}

		client, err := NewNexusClientWithDPoP(serverURL)
		if err != nil {
			return err
		}
		ctx := cmd.Context()

		// Resolve tenant name to ID
		tenants, err := client.ListTenants(ctx)
		if err != nil {
			return fmt.Errorf("failed to list tenants: %w", err)
		}

		var tenantID string
		for _, t := range tenants {
			if t.Name == tenantName || t.ID == tenantName {
				tenantID = t.ID
				break
			}
		}
		if tenantID == "" {
			return fmt.Errorf("tenant not found: %s", tenantName)
		}

		// Resolve CA name to ID
		ca, err := client.GetSSHCA(ctx, caName)
		if err != nil {
			return fmt.Errorf("CA not found: %s", caName)
		}

		// Resolve device names to IDs
		var deviceIDs []string
		if devicesArg == "all" {
			deviceIDs = []string{"all"}
		} else {
			deviceNames := strings.Split(devicesArg, ",")
			dpus, err := client.ListDPUs(ctx, "")
			if err != nil {
				return fmt.Errorf("failed to list DPUs: %w", err)
			}

			for _, name := range deviceNames {
				name = strings.TrimSpace(name)
				found := false
				for _, d := range dpus {
					if d.Name == name || d.ID == name {
						deviceIDs = append(deviceIDs, d.ID)
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("device not found: %s", name)
				}
			}
		}

		// Grant authorization
		resp, err := client.GrantAuthorization(ctx, email, tenantID, []string{ca.ID}, deviceIDs)
		if err != nil {
			return fmt.Errorf("failed to grant authorization: %w", err)
		}

		if outputFormat == "json" || outputFormat == "yaml" {
			return formatOutput(resp)
		}

		fmt.Println("Authorization granted:")
		fmt.Printf("  Operator: %s\n", email)
		fmt.Printf("  Tenant:   %s\n", tenantName)
		fmt.Printf("  CA:       %s\n", caName)
		fmt.Printf("  Devices:  %s\n", devicesArg)
		return nil
	},
}

var operatorAuthorizationsCmd = &cobra.Command{
	Use:   "authorizations <email>",
	Short: "List operator's authorizations",
	Long: `List all authorizations granted to an operator.

Examples:
  bluectl operator authorizations nelson@acme.com`,
	Args: ExactArgsWithUsage(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]

		_, err := requireServer()
		if err != nil {
			return err
		}

		// For now, print informational message
		fmt.Printf("Authorizations for %s:\n", email)
		fmt.Println()
		fmt.Println("Note: Authorization listing via API not yet implemented.")
		fmt.Println("Use the Nexus web interface or API directly.")
		return nil
	},
}

var operatorRevokeCmd = &cobra.Command{
	Use:   "revoke <email>",
	Short: "Revoke specific authorization",
	Long: `Revoke an operator's authorization for a specific CA within a tenant.

Examples:
  bluectl operator revoke nelson@acme.com --tenant acme --ca ops-ca`,
	Args: ExactArgsWithUsage(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		tenantName, _ := cmd.Flags().GetString("tenant")
		caName, _ := cmd.Flags().GetString("ca")

		_, err := requireServer()
		if err != nil {
			return err
		}

		// For now, print informational message
		fmt.Printf("Revoke authorization:\n")
		fmt.Printf("  Operator: %s\n", email)
		fmt.Printf("  Tenant:   %s\n", tenantName)
		fmt.Printf("  CA:       %s\n", caName)
		fmt.Println()
		fmt.Println("Note: Authorization revoke via API not yet implemented.")
		fmt.Println("Use the Nexus web interface or API directly.")
		return nil
	},
}

var operatorRemoveCmd = &cobra.Command{
	Use:     "remove <email>",
	Aliases: []string{"delete"},
	Short:   "Remove an operator",
	Long: `Remove an operator from the server. The operator must not have any keymakers or authorizations.

Use --yes/-y to skip the confirmation prompt.

Examples:
  bluectl operator remove marcus@acme.com
  bluectl operator remove marcus@acme.com --yes`,
	Args: ExactArgsWithUsage(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		yes, _ := cmd.Flags().GetBool("yes")

		// Confirm deletion unless --yes/-y is set
		if !yes {
			fmt.Printf("Are you sure you want to remove operator '%s'? [y/N]: ", email)
			var response string
			fmt.Scanln(&response)
			response = strings.ToLower(strings.TrimSpace(response))
			if response != "y" && response != "yes" {
				fmt.Println("Removal cancelled.")
				return nil
			}
		}

		serverURL, err := requireServer()
		if err != nil {
			return err
		}
		return removeOperatorRemote(cmd.Context(), serverURL, email)
	},
}

func removeOperatorRemote(ctx context.Context, serverURL, email string) error {
	client, err := NewNexusClientWithDPoP(serverURL)
	if err != nil {
		return err
	}
	if err := client.RemoveOperator(ctx, email); err != nil {
		return fmt.Errorf("failed to remove operator: %w", err)
	}
	fmt.Printf("Removed operator '%s'\n", email)
	return nil
}

var operatorSetRoleCmd = &cobra.Command{
	Use:   "set-role <email> <tenant> <role>",
	Short: "Assign or update an operator's role in a tenant",
	Long: `Assign or update an operator's role in a tenant.

Arguments:
  email   Operator email address
  tenant  Tenant name
  role    Role to assign: operator, tenant:admin, or super:admin

Authorization:
  - tenant:admin can assign operator or tenant:admin in their own tenant
  - super:admin can assign any role in any tenant
  - Cannot assign a role higher than your own

Examples:
  bluectl operator set-role alice@example.com acme operator
  bluectl operator set-role alice@example.com acme tenant:admin
  bluectl operator set-role alice@example.com acme super:admin`,
	Args: ExactArgsWithUsage(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		tenantName := args[1]
		role := args[2]

		// Validate role
		validRole := false
		for _, r := range ValidRoles {
			if role == r {
				validRole = true
				break
			}
		}
		if !validRole {
			return fmt.Errorf("invalid role: %s (must be one of: %s)", role, strings.Join(ValidRoles, ", "))
		}

		serverURL, err := requireServer()
		if err != nil {
			return err
		}
		return setRoleRemote(cmd.Context(), serverURL, email, tenantName, role)
	},
}

func setRoleRemote(ctx context.Context, serverURL, email, tenantName, role string, optClient ...*NexusClient) error {
	var client *NexusClient
	var err error
	if len(optClient) > 0 && optClient[0] != nil {
		client = optClient[0]
	} else {
		client, err = NewNexusClientWithDPoP(serverURL)
		if err != nil {
			return err
		}
	}

	// Resolve operator email to ID
	operator, err := client.GetOperator(ctx, email)
	if err != nil {
		return fmt.Errorf("operator not found: %s", email)
	}

	// Resolve tenant name to ID
	tenants, err := client.ListTenants(ctx)
	if err != nil {
		return fmt.Errorf("failed to list tenants: %w", err)
	}

	var tenantID string
	for _, t := range tenants {
		if t.Name == tenantName || t.ID == tenantName {
			tenantID = t.ID
			break
		}
	}
	if tenantID == "" {
		return fmt.Errorf("tenant not found: %s", tenantName)
	}

	// Assign the role
	if err := client.AssignRole(ctx, operator.ID, tenantID, role); err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	fmt.Printf("Role assigned: %s -> %s in %s\n", email, role, tenantName)
	return nil
}

var operatorRemoveRoleCmd = &cobra.Command{
	Use:   "remove-role <email> <tenant>",
	Short: "Remove an operator's role from a tenant",
	Long: `Remove an operator's role from a tenant.

Arguments:
  email   Operator email address
  tenant  Tenant name

Authorization:
  - tenant:admin can remove operator or tenant:admin in their own tenant
  - super:admin can remove any role in any tenant
  - Cannot remove a role equal to or higher than your own

Examples:
  bluectl operator remove-role alice@example.com acme`,
	Args: ExactArgsWithUsage(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		email := args[0]
		tenantName := args[1]

		serverURL, err := requireServer()
		if err != nil {
			return err
		}
		return removeRoleRemote(cmd.Context(), serverURL, email, tenantName)
	},
}

func removeRoleRemote(ctx context.Context, serverURL, email, tenantName string, optClient ...*NexusClient) error {
	var client *NexusClient
	var err error
	if len(optClient) > 0 && optClient[0] != nil {
		client = optClient[0]
	} else {
		client, err = NewNexusClientWithDPoP(serverURL)
		if err != nil {
			return err
		}
	}

	// Resolve operator email to ID
	operator, err := client.GetOperator(ctx, email)
	if err != nil {
		return fmt.Errorf("operator not found: %s", email)
	}

	// Resolve tenant name to ID
	tenants, err := client.ListTenants(ctx)
	if err != nil {
		return fmt.Errorf("failed to list tenants: %w", err)
	}

	var tenantID string
	for _, t := range tenants {
		if t.Name == tenantName || t.ID == tenantName {
			tenantID = t.ID
			break
		}
	}
	if tenantID == "" {
		return fmt.Errorf("tenant not found: %s", tenantName)
	}

	// Remove the role
	if err := client.RemoveRole(ctx, operator.ID, tenantID); err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}

	fmt.Printf("Role removed: %s from %s\n", email, tenantName)
	return nil
}
