// Package timeutil provides human-readable relative time formatting.
//
// # Usage
//
//	timeutil.Relative(time.Now().Add(-5 * time.Minute)) // "5 minutes ago"
//	timeutil.Relative(time.Now().Add(2 * time.Hour))    // "in 2 hours"
package timeutil
