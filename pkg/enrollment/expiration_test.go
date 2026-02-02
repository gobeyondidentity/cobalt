package enrollment

import (
	"testing"
	"time"
)

func TestDefaultTTLs(t *testing.T) {
	t.Parallel()
	t.Log("Verifying default TTL constants")

	if DefaultChallengeTTL != 5*time.Minute {
		t.Errorf("DefaultChallengeTTL = %v, want 5m", DefaultChallengeTTL)
	}

	if DefaultInviteCodeTTL != 1*time.Hour {
		t.Errorf("DefaultInviteCodeTTL = %v, want 1h", DefaultInviteCodeTTL)
	}
}

func TestIsChallengeExpired(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		created time.Time
		now     time.Time
		want    bool
	}{
		{
			name:    "NotExpired_JustCreated",
			created: time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC),
			now:     time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC),
			want:    false,
		},
		{
			name:    "NotExpired_4Minutes",
			created: time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC),
			now:     time.Date(2026, 1, 30, 10, 4, 0, 0, time.UTC),
			want:    false,
		},
		{
			name:    "NotExpired_Exactly5Minutes",
			created: time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC),
			now:     time.Date(2026, 1, 30, 10, 5, 0, 0, time.UTC),
			want:    false,
		},
		{
			name:    "Expired_5Minutes1Second",
			created: time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC),
			now:     time.Date(2026, 1, 30, 10, 5, 1, 0, time.UTC),
			want:    true,
		},
		{
			name:    "Expired_1Hour",
			created: time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC),
			now:     time.Date(2026, 1, 30, 11, 0, 0, 0, time.UTC),
			want:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Checking challenge created at %v against now=%v", tc.created, tc.now)
			got := IsChallengeExpired(tc.created, tc.now)
			if got != tc.want {
				t.Errorf("IsChallengeExpired(%v, %v) = %v, want %v", tc.created, tc.now, got, tc.want)
			}
		})
	}
}

func TestIsInviteCodeExpired(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		created time.Time
		now     time.Time
		want    bool
	}{
		{
			name:    "NotExpired_JustCreated",
			created: time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC),
			now:     time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC),
			want:    false,
		},
		{
			name:    "NotExpired_30Minutes",
			created: time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC),
			now:     time.Date(2026, 1, 30, 10, 30, 0, 0, time.UTC),
			want:    false,
		},
		{
			name:    "NotExpired_Exactly1Hour",
			created: time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC),
			now:     time.Date(2026, 1, 30, 11, 0, 0, 0, time.UTC),
			want:    false,
		},
		{
			name:    "Expired_1Hour1Second",
			created: time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC),
			now:     time.Date(2026, 1, 30, 11, 0, 1, 0, time.UTC),
			want:    true,
		},
		{
			name:    "Expired_2Hours",
			created: time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC),
			now:     time.Date(2026, 1, 30, 12, 0, 0, 0, time.UTC),
			want:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Checking invite code created at %v against now=%v", tc.created, tc.now)
			got := IsInviteCodeExpired(tc.created, tc.now)
			if got != tc.want {
				t.Errorf("IsInviteCodeExpired(%v, %v) = %v, want %v", tc.created, tc.now, got, tc.want)
			}
		})
	}
}

func TestExpirationBoundaryPrecision(t *testing.T) {
	t.Parallel()
	t.Log("Testing nanosecond precision at boundaries")

	base := time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC)

	// Challenge: exactly at 5 minute boundary
	challengeExact := base.Add(DefaultChallengeTTL)
	if IsChallengeExpired(base, challengeExact) {
		t.Error("Challenge should not be expired exactly at TTL boundary")
	}

	// Challenge: 1 nanosecond past boundary
	challengePast := base.Add(DefaultChallengeTTL + time.Nanosecond)
	if !IsChallengeExpired(base, challengePast) {
		t.Error("Challenge should be expired 1ns past TTL boundary")
	}

	// Invite: exactly at 1 hour boundary
	inviteExact := base.Add(DefaultInviteCodeTTL)
	if IsInviteCodeExpired(base, inviteExact) {
		t.Error("Invite code should not be expired exactly at TTL boundary")
	}

	// Invite: 1 nanosecond past boundary
	invitePast := base.Add(DefaultInviteCodeTTL + time.Nanosecond)
	if !IsInviteCodeExpired(base, invitePast) {
		t.Error("Invite code should be expired 1ns past TTL boundary")
	}
}
