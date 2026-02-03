package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestExtractArgNames(t *testing.T) {
	t.Log("Testing argument name extraction from Use strings")

	tests := []struct {
		name string
		use  string
		want []string
	}{
		{
			name: "single required arg",
			use:  "delete <trust-id>",
			want: []string{"<trust-id>"},
		},
		{
			name: "multiple required args",
			use:  "grant <email> <tenant> <ca> <devices>",
			want: []string{"<email>", "<tenant>", "<ca>", "<devices>"},
		},
		{
			name: "optional arg",
			use:  "invite <email> <tenant> [role]",
			want: []string{"<email>", "<tenant>", "[role]"},
		},
		{
			name: "no args",
			use:  "list",
			want: nil,
		},
		{
			name: "command with subcommand path",
			use:  "create <source-host> <target-host>",
			want: []string{"<source-host>", "<target-host>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Use string: %q", tt.use)
			got := extractArgNames(tt.use)
			if len(got) != len(tt.want) {
				t.Errorf("extractArgNames(%q) = %v, want %v", tt.use, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("extractArgNames(%q)[%d] = %q, want %q", tt.use, i, got[i], tt.want[i])
				}
			}
			t.Logf("Extracted: %v (correct)", got)
		})
	}
}

func TestExactArgsWithUsage(t *testing.T) {
	t.Log("Testing ExactArgsWithUsage provides helpful error messages")

	cmd := &cobra.Command{
		Use: "grant <email> <tenant> <ca> <devices>",
	}
	cmd.SetUsageTemplate("") // Prevent default usage output

	validator := ExactArgsWithUsage(4)

	// Test with correct number of args
	t.Run("correct arg count", func(t *testing.T) {
		err := validator(cmd, []string{"a@b.com", "tenant", "ca", "all"})
		if err != nil {
			t.Errorf("Expected no error with 4 args, got: %v", err)
		}
		t.Log("4 args accepted correctly")
	})

	// Test with wrong number of args
	t.Run("wrong arg count shows usage", func(t *testing.T) {
		err := validator(cmd, []string{"a@b.com", "tenant"})
		if err == nil {
			t.Error("Expected error with 2 args, got nil")
			return
		}

		errMsg := err.Error()
		t.Logf("Error message:\n%s", errMsg)

		// Check that error message contains helpful info
		if !strings.Contains(errMsg, "requires 4 argument(s)") {
			t.Error("Error should mention required argument count")
		}
		if !strings.Contains(errMsg, "received 2") {
			t.Error("Error should mention received argument count")
		}
		if !strings.Contains(errMsg, "Usage:") {
			t.Error("Error should include usage line")
		}
		if !strings.Contains(errMsg, "<email>") {
			t.Error("Error should list argument names")
		}
		if !strings.Contains(errMsg, "--help") {
			t.Error("Error should suggest --help")
		}
		t.Log("Error message contains all required information")
	})
}

func TestRangeArgsWithUsage(t *testing.T) {
	t.Log("Testing RangeArgsWithUsage provides helpful error messages")

	cmd := &cobra.Command{
		Use: "invite <email> <tenant> [role]",
	}
	cmd.SetUsageTemplate("")

	validator := RangeArgsWithUsage(2, 3)

	// Test with correct number of args
	t.Run("min args accepted", func(t *testing.T) {
		err := validator(cmd, []string{"a@b.com", "tenant"})
		if err != nil {
			t.Errorf("Expected no error with 2 args, got: %v", err)
		}
		t.Log("2 args (min) accepted correctly")
	})

	t.Run("max args accepted", func(t *testing.T) {
		err := validator(cmd, []string{"a@b.com", "tenant", "admin"})
		if err != nil {
			t.Errorf("Expected no error with 3 args, got: %v", err)
		}
		t.Log("3 args (max) accepted correctly")
	})

	// Test with too few args
	t.Run("too few args shows usage", func(t *testing.T) {
		err := validator(cmd, []string{"a@b.com"})
		if err == nil {
			t.Error("Expected error with 1 arg, got nil")
			return
		}

		errMsg := err.Error()
		t.Logf("Error message:\n%s", errMsg)

		if !strings.Contains(errMsg, "requires 2-3 argument(s)") {
			t.Error("Error should mention required argument range")
		}
		t.Log("Error message shows argument range correctly")
	})

	// Test with too many args
	t.Run("too many args shows usage", func(t *testing.T) {
		err := validator(cmd, []string{"a@b.com", "tenant", "admin", "extra"})
		if err == nil {
			t.Error("Expected error with 4 args, got nil")
			return
		}

		errMsg := err.Error()
		if !strings.Contains(errMsg, "received 4") {
			t.Error("Error should mention received argument count")
		}
		t.Log("Too many args error shown correctly")
	})
}
