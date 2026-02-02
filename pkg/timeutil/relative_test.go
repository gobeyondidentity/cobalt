// Package timeutil provides time formatting utilities for CLI output.
package timeutil

import (
	"testing"
	"time"
)

func TestRelativeTime(t *testing.T) {
	t.Parallel()
	// Use a fixed reference time for deterministic testing
	now := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		t        time.Time
		expected string
	}{
		// Future times
		{"in 30 seconds", now.Add(30 * time.Second), "in less than a minute"},
		{"in 1 minute", now.Add(1 * time.Minute), "in 1 minute"},
		{"in 2 minutes", now.Add(2 * time.Minute), "in 2 minutes"},
		{"in 30 minutes", now.Add(30 * time.Minute), "in 30 minutes"},
		{"in 1 hour", now.Add(1 * time.Hour), "in 1 hour"},
		{"in 2 hours", now.Add(2 * time.Hour), "in 2 hours"},
		{"in 23 hours", now.Add(23 * time.Hour), "in 23 hours"},
		{"in 24 hours", now.Add(24 * time.Hour), "in 1 day"},
		{"in 36 hours", now.Add(36 * time.Hour), "in 1 day"},
		{"in 2 days", now.Add(48 * time.Hour), "in 2 days"},
		{"in 7 days", now.Add(7 * 24 * time.Hour), "in 7 days"},
		{"in 14 days", now.Add(14 * 24 * time.Hour), "in 2 weeks"},
		{"in 30 days", now.Add(30 * 24 * time.Hour), "in 4 weeks"},
		{"in 60 days", now.Add(60 * 24 * time.Hour), "in 2 months"},

		// Past times
		{"30 seconds ago", now.Add(-30 * time.Second), "less than a minute ago"},
		{"1 minute ago", now.Add(-1 * time.Minute), "1 minute ago"},
		{"2 minutes ago", now.Add(-2 * time.Minute), "2 minutes ago"},
		{"30 minutes ago", now.Add(-30 * time.Minute), "30 minutes ago"},
		{"1 hour ago", now.Add(-1 * time.Hour), "1 hour ago"},
		{"2 hours ago", now.Add(-2 * time.Hour), "2 hours ago"},
		{"23 hours ago", now.Add(-23 * time.Hour), "23 hours ago"},
		{"24 hours ago", now.Add(-24 * time.Hour), "1 day ago"},
		{"36 hours ago", now.Add(-36 * time.Hour), "1 day ago"},
		{"2 days ago", now.Add(-48 * time.Hour), "2 days ago"},
		{"7 days ago", now.Add(-7 * 24 * time.Hour), "7 days ago"},
		{"14 days ago", now.Add(-14 * 24 * time.Hour), "2 weeks ago"},
		{"30 days ago", now.Add(-30 * 24 * time.Hour), "4 weeks ago"},
		{"60 days ago", now.Add(-60 * 24 * time.Hour), "2 months ago"},

		// Edge case: now
		{"now", now, "just now"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RelativeTimeWithNow(tt.t, now)
			if got != tt.expected {
				t.Errorf("RelativeTimeWithNow(%v, %v) = %q, want %q", tt.t, now, got, tt.expected)
			}
		})
	}
}

func TestRelativeTimeWithNow(t *testing.T) {
	t.Parallel()
	// Use a fixed reference time for deterministic testing
	ref := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		t        time.Time
		now      time.Time
		expected string
	}{
		{"future 1 hour", ref.Add(1 * time.Hour), ref, "in 1 hour"},
		{"past 1 hour", ref.Add(-1 * time.Hour), ref, "1 hour ago"},
		{"future 24 hours", ref.Add(24 * time.Hour), ref, "in 1 day"},
		{"past 24 hours", ref.Add(-24 * time.Hour), ref, "1 day ago"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RelativeTimeWithNow(tt.t, tt.now)
			if got != tt.expected {
				t.Errorf("RelativeTimeWithNow(%v, %v) = %q, want %q", tt.t, tt.now, got, tt.expected)
			}
		})
	}
}

func TestFormatExpiration(t *testing.T) {
	t.Parallel()
	// Use a fixed reference time for deterministic testing
	now := time.Date(2026, 1, 10, 11, 14, 0, 0, time.Local)

	tests := []struct {
		name     string
		t        time.Time
		expected string
	}{
		{
			"24 hours from now",
			now.Add(24 * time.Hour),
			"Jan 11, 2026 at 11:14 AM (in 1 day)",
		},
		{
			"1 hour from now",
			now.Add(1 * time.Hour),
			"Jan 10, 2026 at 12:14 PM (in 1 hour)",
		},
		{
			"2 hours ago (expired)",
			now.Add(-2 * time.Hour),
			"Jan 10, 2026 at 9:14 AM (2 hours ago)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatExpirationWithNow(tt.t, now)
			if got != tt.expected {
				t.Errorf("FormatExpirationWithNow(%v, %v) = %q, want %q", tt.t, now, got, tt.expected)
			}
		})
	}
}

func TestFormatSimpleExpiration(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 10, 11, 14, 0, 0, time.Local)

	tests := []struct {
		name     string
		t        time.Time
		expected string
	}{
		{"24 hours", now.Add(24 * time.Hour), "Expires in 1 day"},
		{"1 hour", now.Add(1 * time.Hour), "Expires in 1 hour"},
		{"expired", now.Add(-2 * time.Hour), "Expired 2 hours ago"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatSimpleExpirationWithNow(tt.t, now)
			if got != tt.expected {
				t.Errorf("FormatSimpleExpirationWithNow(%v, %v) = %q, want %q", tt.t, now, got, tt.expected)
			}
		})
	}
}
