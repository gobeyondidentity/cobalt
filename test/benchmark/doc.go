//go:build benchmark

// Package benchmark contains consolidated benchmark tests for secure-infra.
//
// This package aggregates benchmarks from across the codebase to enable
// easy performance regression testing.
//
// Run with: go test -tags=benchmark -bench=. -benchmem ./test/benchmark/...
//
// Benchmarks are organized by component:
//   - transport_bench_test.go: Transport layer (DOCA ComCh, message serialization)
//   - dpop_bench_test.go: DPoP validation and JTI cache
//   - store_bench_test.go: Database operations
//   - tmfifo_bench_test.go: TMFIFO protocol handling
package benchmark
