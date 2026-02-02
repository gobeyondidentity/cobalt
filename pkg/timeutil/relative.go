package timeutil

import (
	"fmt"
	"time"
)

// RelativeTime returns a human-readable relative time string.
// Examples: "in 24 hours", "2 hours ago", "in 3 days"
func RelativeTime(t time.Time) string {
	return RelativeTimeWithNow(t, time.Now())
}

// RelativeTimeWithNow returns a human-readable relative time string
// using the provided reference time instead of time.Now().
// This is useful for testing and deterministic output.
func RelativeTimeWithNow(t, now time.Time) string {
	diff := t.Sub(now)
	absDiff := diff
	if absDiff < 0 {
		absDiff = -absDiff
	}

	// Handle "just now" case
	if absDiff < time.Second {
		return "just now"
	}

	// Calculate units
	seconds := int(absDiff.Seconds())
	minutes := int(absDiff.Minutes())
	hours := int(absDiff.Hours())
	days := hours / 24
	weeks := days / 7
	months := days / 30

	var unit string
	var value int

	switch {
	case seconds < 60:
		// Less than a minute
		if diff > 0 {
			return "in less than a minute"
		}
		return "less than a minute ago"
	case minutes < 60:
		value = minutes
		unit = "minute"
	case hours < 24:
		value = hours
		unit = "hour"
	case days < 14:
		value = days
		unit = "day"
	case days < 60:
		value = weeks
		unit = "week"
	default:
		value = months
		unit = "month"
	}

	// Pluralize
	if value != 1 {
		unit += "s"
	}

	// Future or past
	if diff > 0 {
		return fmt.Sprintf("in %d %s", value, unit)
	}
	return fmt.Sprintf("%d %s ago", value, unit)
}

// FormatExpiration returns a formatted expiration time with both
// absolute and relative time for CLI display.
// Example: "Jan 10, 2026 at 11:14 AM (in 24 hours)"
func FormatExpiration(t time.Time) string {
	return FormatExpirationWithNow(t, time.Now())
}

// FormatExpirationWithNow returns a formatted expiration time using
// the provided reference time instead of time.Now().
func FormatExpirationWithNow(t, now time.Time) string {
	absolute := t.Format("Jan 2, 2006 at 3:04 PM")
	relative := RelativeTimeWithNow(t, now)
	return fmt.Sprintf("%s (%s)", absolute, relative)
}

// FormatSimpleExpiration returns a simple expiration string.
// Example: "Expires in 24 hours" or "Expired 2 hours ago"
func FormatSimpleExpiration(t time.Time) string {
	return FormatSimpleExpirationWithNow(t, time.Now())
}

// FormatSimpleExpirationWithNow returns a simple expiration string
// using the provided reference time instead of time.Now().
func FormatSimpleExpirationWithNow(t, now time.Time) string {
	relative := RelativeTimeWithNow(t, now)
	if t.After(now) {
		return fmt.Sprintf("Expires %s", relative)
	}
	return fmt.Sprintf("Expired %s", relative)
}
