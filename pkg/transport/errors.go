// This file has no build tags so errors are available in all build configurations.
package transport

import "errors"

// ErrDOCANotAvailable is returned when DOCA SDK is not available.
var ErrDOCANotAvailable = errors.New("DOCA ComCh requires BlueField hardware and DOCA SDK")
