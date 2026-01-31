package enrollment

import "time"

// Default TTL values for enrollment operations.
const (
	// DefaultChallengeTTL is the time window during which a challenge is valid.
	// After this period, the challenge must be regenerated.
	DefaultChallengeTTL = 5 * time.Minute

	// DefaultInviteCodeTTL is the time window during which an invite code is valid.
	// After this period, the invite code expires and a new one must be issued.
	DefaultInviteCodeTTL = 1 * time.Hour
)

// IsChallengeExpired checks if a challenge has exceeded its TTL.
//
// Parameters:
//   - createdAt: when the challenge was generated
//   - now: the current time (pass time.Now() at callsite)
//
// Returns true if now > createdAt + DefaultChallengeTTL.
//
// SECURITY: Pass time.Now() at the callsite rather than relying on
// internal time.Now() calls to avoid TOCTOU (time-of-check-to-time-of-use)
// races in security-critical code paths.
func IsChallengeExpired(createdAt, now time.Time) bool {
	return now.After(createdAt.Add(DefaultChallengeTTL))
}

// IsInviteCodeExpired checks if an invite code has exceeded its TTL.
//
// Parameters:
//   - createdAt: when the invite code was generated
//   - now: the current time (pass time.Now() at callsite)
//
// Returns true if now > createdAt + DefaultInviteCodeTTL.
//
// SECURITY: Pass time.Now() at the callsite rather than relying on
// internal time.Now() calls to avoid TOCTOU (time-of-check-to-time-of-use)
// races in security-critical code paths.
func IsInviteCodeExpired(createdAt, now time.Time) bool {
	return now.After(createdAt.Add(DefaultInviteCodeTTL))
}
