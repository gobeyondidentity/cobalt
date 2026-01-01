package main

/*
#cgo LDFLAGS: -lPKA
#include <pka.h>
#include <stdlib.h>
#include <string.h>

// P-256 curve parameters (NIST secp256r1)
// Now in LITTLE-ENDIAN order (reversed bytes)

// Prime p (little-endian)
static uint8_t p256_p[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
};

// Coefficient a = -3 mod p (little-endian)
static uint8_t p256_a[] = {
    0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
};

// Coefficient b (little-endian)
static uint8_t p256_b[] = {
    0x4b, 0x60, 0xd2, 0x27, 0x3e, 0x3c, 0xce, 0x3b,
    0xf6, 0xb0, 0x53, 0xcc, 0xb0, 0x06, 0x1d, 0x65,
    0xbc, 0x86, 0x98, 0x76, 0x55, 0xbd, 0xeb, 0xb3,
    0xe7, 0x93, 0x3a, 0xaa, 0xd8, 0x35, 0xc6, 0x5a
};

// Generator point G - x coordinate (little-endian)
static uint8_t p256_gx[] = {
    0x96, 0xc2, 0x98, 0xd8, 0x45, 0x39, 0xa1, 0xf4,
    0xa0, 0x33, 0xeb, 0x2d, 0x81, 0x7d, 0x03, 0x77,
    0xf2, 0x40, 0xa4, 0x63, 0xe5, 0xe6, 0xbc, 0xf8,
    0x47, 0x42, 0x2c, 0xe1, 0xf2, 0xd1, 0x17, 0x6b
};

// Generator point G - y coordinate (little-endian)
static uint8_t p256_gy[] = {
    0xf5, 0x51, 0xbf, 0x37, 0x68, 0x40, 0xb6, 0xcb,
    0xce, 0x5e, 0x31, 0x6b, 0x57, 0x33, 0xce, 0x2b,
    0x16, 0x9e, 0x0f, 0x7c, 0x4a, 0xeb, 0xe7, 0x8e,
    0x9b, 0x7f, 0x1a, 0xfe, 0xe2, 0x42, 0xe3, 0x4f
};

// Result buffers (must be pre-allocated for PKA results)
static uint8_t result_x_buf[32];
static uint8_t result_y_buf[32];

// Helper to create operand from buffer
static void init_operand(pka_operand_t* op, uint8_t* buf, uint16_t len, uint8_t big_endian) {
    memset(op, 0, sizeof(pka_operand_t));
    op->buf_ptr = buf;
    op->buf_len = len;
    op->actual_len = len;
    op->big_endian = big_endian;
}

// Helper to setup the P-256 curve (little-endian)
static void setup_p256_curve(ecc_curve_t* curve) {
    init_operand(&curve->p, p256_p, 32, 0);  // 0 = little-endian
    init_operand(&curve->a, p256_a, 32, 0);
    init_operand(&curve->b, p256_b, 32, 0);
}

// Helper to setup generator point G (little-endian)
static void setup_p256_generator(ecc_point_t* point) {
    init_operand(&point->x, p256_gx, 32, 0);
    init_operand(&point->y, p256_gy, 32, 0);
}

// Allocate C memory for scalar and copy data
static uint8_t* alloc_scalar(void* go_data, int len) {
    uint8_t* buf = (uint8_t*)malloc(len);
    if (buf) {
        memcpy(buf, go_data, len);
    }
    return buf;
}

// Initialize results structure with pre-allocated buffers
static void init_results(pka_results_t* results) {
    memset(results, 0, sizeof(pka_results_t));
    // Pre-allocate result buffers for ECC point (x, y coordinates)
    results->results[0].buf_ptr = result_x_buf;
    results->results[0].buf_len = 32;
    results->results[1].buf_ptr = result_y_buf;
    results->results[1].buf_len = 32;
}

// Get result X buffer
static uint8_t* get_result_x() { return result_x_buf; }
static uint8_t* get_result_y() { return result_y_buf; }

// Reverse bytes in place
static void reverse_bytes(uint8_t* buf, int len) {
    for (int i = 0; i < len / 2; i++) {
        uint8_t tmp = buf[i];
        buf[i] = buf[len - 1 - i];
        buf[len - 1 - i] = tmp;
    }
}
*/
import "C"
import (
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "unsafe"
)

// reverseBytes reverses a byte slice in place
func reverseBytes(b []byte) {
    for i := 0; i < len(b)/2; i++ {
        b[i], b[len(b)-1-i] = b[len(b)-1-i], b[i]
    }
}

// isZero checks if all bytes in a slice are zero.
// Used to validate cryptographic scalars are non-zero.
func isZero(b []byte) bool {
    for _, v := range b {
        if v != 0 {
            return false
        }
    }
    return true
}

func main() {
    fmt.Println("=== PKA ECDSA Key Generation ===")
    fmt.Println()

    // Step 1: Initialize PKA
    fmt.Println("[1] Initializing PKA...")
    pkaName := C.CString("go-ecdsa-keygen")
    defer C.free(unsafe.Pointer(pkaName)) // Fix memory leak: free CString
    instance := C.pka_init_global(
        pkaName,
        C.PKA_F_PROCESS_MODE_SINGLE|C.PKA_F_SYNC_MODE_ENABLE,
        1, 1, 4096, 4096,
    )
    if instance == C.PKA_INSTANCE_INVALID {
        fmt.Println("ERROR: pka_init_global failed")
        return
    }
    defer C.pka_term_global(instance)

    handle := C.pka_init_local(instance)
    if handle == nil {
        fmt.Println("ERROR: pka_init_local failed")
        return
    }
    defer C.pka_term_local(handle)
    fmt.Println("    PKA initialized")

    // Step 2: Generate random scalar (private key)
    fmt.Println("[2] Generating random scalar (private key)...")
    scalarGo := make([]byte, 32)
    for {
        _, err := rand.Read(scalarGo)
        if err != nil {
            fmt.Printf("ERROR: Failed to generate random: %v\n", err)
            return
        }
        if !isZero(scalarGo) {
            break
        }
    }
    
    // Save original for display (big-endian)
    scalarDisplay := make([]byte, 32)
    copy(scalarDisplay, scalarGo)
    
    // Convert to little-endian for PKA
    reverseBytes(scalarGo)
    
    fmt.Printf("    Private key (d): %s...\n", hex.EncodeToString(scalarDisplay[:8]))

    // Allocate scalar in C memory
    scalarC := C.alloc_scalar(unsafe.Pointer(&scalarGo[0]), 32)
    if scalarC == nil {
        fmt.Println("ERROR: Failed to allocate scalar")
        return
    }
    defer C.free(unsafe.Pointer(scalarC))

    // Step 3: Setup curve and generator point
    fmt.Println("[3] Setting up P-256 curve parameters...")
    var curve C.ecc_curve_t
    var generator C.ecc_point_t
    C.setup_p256_curve(&curve)
    C.setup_p256_generator(&generator)
    fmt.Println("    Curve: secp256r1 (P-256) [little-endian]")

    // Step 4: Setup scalar operand (using C memory, little-endian)
    var scalarOp C.pka_operand_t
    C.init_operand(&scalarOp, scalarC, 32, 0)  // 0 = little-endian

    // Step 5: Initialize results with pre-allocated buffers
    var results C.pka_results_t
    C.init_results(&results)

    // Step 6: Call PKA ECC point multiplication: Q = d * G
    fmt.Println("[4] Computing public key Q = d * G using PKA...")
    ret := C.pka_ecc_pt_mult(handle, nil, &curve, &generator, &scalarOp)
    if ret != 0 {
        fmt.Printf("ERROR: pka_ecc_pt_mult failed with code %d\n", ret)
        return
    }

    // Step 7: Get the result
    fmt.Println("[5] Retrieving result...")
    
    // Wait for result to be available
    for !C.pka_has_avail_result(handle) {
        // Busy wait
    }

    ret = C.pka_get_result(handle, &results)
    if ret != 0 {
        fmt.Printf("ERROR: pka_get_result failed with code %d\n", ret)
        return
    }

    if results.status != C.RC_NO_ERROR {
        fmt.Printf("ERROR: PKA operation failed with status %d (0x%x)\n", results.status, results.status)
        return
    }

    // Step 8: Extract public key coordinates from pre-allocated buffers
    fmt.Println("[6] Extracting public key coordinates...")
    fmt.Printf("    Result count: %d\n", results.result_cnt)
    
    resultX := C.GoBytes(unsafe.Pointer(C.get_result_x()), 32)
    resultY := C.GoBytes(unsafe.Pointer(C.get_result_y()), 32)
    
    // Convert results back to big-endian for display
    reverseBytes(resultX)
    reverseBytes(resultY)

    // Step 9: Display results
    fmt.Println()
    fmt.Println("=== ECDSA Key Generated ===")
    fmt.Println()
    fmt.Printf("Private Key (d):\n  %s\n", hex.EncodeToString(scalarDisplay))
    fmt.Println()
    fmt.Printf("Public Key (Q):\n")
    fmt.Printf("  X: %s\n", hex.EncodeToString(resultX))
    fmt.Printf("  Y: %s\n", hex.EncodeToString(resultY))
    fmt.Println()
    
    // Uncompressed public key format: 04 || X || Y
    pubKey := append([]byte{0x04}, resultX...)
    pubKey = append(pubKey, resultY...)
    fmt.Printf("Public Key (uncompressed, 65 bytes):\n  %s\n", hex.EncodeToString(pubKey))
    fmt.Println()
    fmt.Println("=== Key generation complete ===")
}
