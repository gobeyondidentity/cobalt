package dpop

import "errors"

var (
	// ErrReplay indicates a JTI has already been used and this is a replay attempt.
	ErrReplay = errors.New("jti replay detected")

	// ErrInvalidJTI indicates the JTI is empty or otherwise invalid.
	ErrInvalidJTI = errors.New("invalid jti: must be non-empty")

	// ErrJTITooLong indicates the JTI exceeds the maximum allowed length.
	ErrJTITooLong = errors.New("jti too long: maximum 1024 bytes")

	// ErrCacheFull indicates the cache has reached its maximum entry count.
	ErrCacheFull = errors.New("jti cache full: maximum entries reached")
)
