package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// ExactArgsWithUsage returns a validator that requires exactly n arguments.
// If the count is wrong, it shows the command's usage with argument names.
func ExactArgsWithUsage(n int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) != n {
			return argsError(cmd, n, n, len(args))
		}
		return nil
	}
}

// RangeArgsWithUsage returns a validator that requires between min and max arguments.
// If the count is wrong, it shows the command's usage with argument names.
func RangeArgsWithUsage(min, max int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) < min || len(args) > max {
			return argsError(cmd, min, max, len(args))
		}
		return nil
	}
}

// argsError creates a helpful error message showing expected usage.
func argsError(cmd *cobra.Command, min, max, got int) error {
	// Extract argument names from Use string
	// Use string is like "grant <email> <tenant> <ca> <devices>"
	argNames := extractArgNames(cmd.Use)

	var expected string
	if min == max {
		expected = fmt.Sprintf("%d", min)
	} else {
		expected = fmt.Sprintf("%d-%d", min, max)
	}

	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("requires %s argument(s), received %d\n\n", expected, got))
	msg.WriteString(fmt.Sprintf("Usage: %s %s\n", cmd.CommandPath(), strings.Join(argNames, " ")))

	// Add argument descriptions if available
	if len(argNames) > 0 {
		msg.WriteString("\nArguments:\n")
		for _, arg := range argNames {
			// Clean up the angle brackets for display
			cleanArg := strings.TrimPrefix(strings.TrimSuffix(arg, ">"), "<")
			cleanArg = strings.TrimPrefix(strings.TrimSuffix(cleanArg, "]"), "[")
			msg.WriteString(fmt.Sprintf("  %s\n", cleanArg))
		}
	}

	msg.WriteString(fmt.Sprintf("\nRun '%s --help' for details.", cmd.CommandPath()))

	return fmt.Errorf("%s", msg.String())
}

// extractArgNames extracts argument names from a Use string.
// For example: "grant <email> <tenant> <ca> <devices>" returns ["<email>", "<tenant>", "<ca>", "<devices>"]
func extractArgNames(use string) []string {
	parts := strings.Fields(use)
	var args []string

	// Skip the command name (first part)
	for _, part := range parts[1:] {
		// Include arguments (both <required> and [optional])
		if strings.HasPrefix(part, "<") || strings.HasPrefix(part, "[") {
			args = append(args, part)
		}
	}

	return args
}
