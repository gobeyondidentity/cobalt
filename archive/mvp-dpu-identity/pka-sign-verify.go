package main

/*
#cgo LDFLAGS: -lPKA
#include <pka.h>
#include <stdlib.h>
#include <string.h>

// P-256 curve parameters (NIST secp256r1) - LITTLE-ENDIAN

// Prime p
static uint8_t p256_p[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
};

// Coefficient a = -3 mod p
static uint8_t p256_a[] = {
    0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
};

// Coefficient b
static uint8_t p256_b[] = {
    0x4b, 0x60, 0xd2, 0x27, 0x3e, 0x3c, 0xce, 0x3b,
    0xf6, 0xb0, 0x53, 0xcc, 0xb0, 0x06, 0x1d, 0x65,
    0xbc, 0x86, 0x98, 0x76, 0x55, 0xbd, 0xeb, 0xb3,
    0xe7, 0x93, 0x3a, 0xaa, 0xd8, 0x35, 0xc6, 0x5a
};

// Generator point G - x coordinate
static uint8_t p256_gx[] = {
    0x96, 0xc2, 0x98, 0xd8, 0x45, 0x39, 0xa1, 0xf4,
    0xa0, 0x33, 0xeb, 0x2d, 0x81, 0x7d, 0x03, 0x77,
    0xf2, 0x40, 0xa4, 0x63, 0xe5, 0xe6, 0xbc, 0xf8,
    0x47, 0x42, 0x2c, 0xe1, 0xf2, 0xd1, 0x17, 0x6b
};

// Generator point G - y coordinate
static uint8_t p256_gy[] = {
    0xf5, 0x51, 0xbf, 0x37, 0x68, 0x40, 0xb6, 0xcb,
    0xce, 0x5e, 0x31, 0x6b, 0x57, 0x33, 0xce, 0x2b,
    0x16, 0x9e, 0x0f, 0x7c, 0x4a, 0xeb, 0xe7, 0x8e,
    0x9b, 0x7f, 0x1a, 0xfe, 0xe2, 0x42, 0xe3, 0x4f
};

// Curve order n (little-endian)
// n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
static uint8_t p256_n[] = {
    0x51, 0x25, 0x63, 0xfc, 0xc2, 0xca, 0xb9, 0xf3,
    0x84, 0x9e, 0x17, 0xa7, 0xad, 0xfa, 0xe6, 0xbc,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
};

// Result buffers
static uint8_t result_x_buf[32];
static uint8_t result_y_buf[32];
static uint8_t sig_r_buf[32];
static uint8_t sig_s_buf[32];

// Helper functions
static void init_operand(pka_operand_t* op, uint8_t* buf, uint16_t len, uint8_t big_endian) {
    memset(op, 0, sizeof(pka_operand_t));
    op->buf_ptr = buf;
    op->buf_len = len;
    op->actual_len = len;
    op->big_endian = big_endian;
}

static void setup_p256_curve(ecc_curve_t* curve) {
    init_operand(&curve->p, p256_p, 32, 0);
    init_operand(&curve->a, p256_a, 32, 0);
    init_operand(&curve->b, p256_b, 32, 0);
}

static void setup_p256_generator(ecc_point_t* point) {
    init_operand(&point->x, p256_gx, 32, 0);
    init_operand(&point->y, p256_gy, 32, 0);
}

static void setup_p256_order(pka_operand_t* order) {
    init_operand(order, p256_n, 32, 0);
}

static uint8_t* alloc_copy(void* data, int len) {
    uint8_t* buf = (uint8_t*)malloc(len);
    if (buf) memcpy(buf, data, len);
    return buf;
}

static void init_keygen_results(pka_results_t* results) {
    memset(results, 0, sizeof(pka_results_t));
    results->results[0].buf_ptr = result_x_buf;
    results->results[0].buf_len = 32;
    results->results[1].buf_ptr = result_y_buf;
    results->results[1].buf_len = 32;
}

static void init_sign_results(pka_results_t* results) {
    memset(results, 0, sizeof(pka_results_t));
    results->results[0].buf_ptr = sig_r_buf;
    results->results[0].buf_len = 32;
    results->results[1].buf_ptr = sig_s_buf;
    results->results[1].buf_len = 32;
}

static void init_verify_results(pka_results_t* results) {
    memset(results, 0, sizeof(pka_results_t));
    // Verify returns no data, just status
}

static uint8_t* get_result_x() { return result_x_buf; }
static uint8_t* get_result_y() { return result_y_buf; }
static uint8_t* get_sig_r() { return sig_r_buf; }
static uint8_t* get_sig_s() { return sig_s_buf; }
*/
import "C"
import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "unsafe"
)

func reverseBytes(b []byte) {
    for i := 0; i < len(b)/2; i++ {
        b[i], b[len(b)-1-i] = b[len(b)-1-i], b[i]
    }
}

// isZero checks if all bytes in a slice are zero.
// Used to validate cryptographic nonces are non-zero.
func isZero(b []byte) bool {
    for _, v := range b {
        if v != 0 {
            return false
        }
    }
    return true
}

func main() {
    fmt.Println("=== PKA ECDSA Sign & Verify Demo ===")
    fmt.Println()

    // Initialize PKA
    fmt.Println("[1] Initializing PKA...")
    pkaName := C.CString("go-ecdsa-demo")
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

    // Setup curve parameters
    var curve C.ecc_curve_t
    var generator C.ecc_point_t
    var order C.pka_operand_t
    C.setup_p256_curve(&curve)
    C.setup_p256_generator(&generator)
    C.setup_p256_order(&order)

    // ========== KEY GENERATION ==========
    fmt.Println("\n[2] Generating ECDSA keypair...")
    
    // Generate private key (random scalar d)
    privateKeyGo := make([]byte, 32)
    for {
        _, err := rand.Read(privateKeyGo)
        if err != nil {
            fmt.Printf("ERROR: Failed to generate private key: %v\n", err)
            return
        }
        if !isZero(privateKeyGo) {
            break
        }
    }
    privateKeyDisplay := make([]byte, 32)
    copy(privateKeyDisplay, privateKeyGo)
    reverseBytes(privateKeyGo) // Convert to little-endian
    
    privateKeyC := C.alloc_copy(unsafe.Pointer(&privateKeyGo[0]), 32)
    defer C.free(unsafe.Pointer(privateKeyC))
    
    var privateKeyOp C.pka_operand_t
    C.init_operand(&privateKeyOp, privateKeyC, 32, 0)

    // Compute public key Q = d * G
    var keygenResults C.pka_results_t
    C.init_keygen_results(&keygenResults)
    
    ret := C.pka_ecc_pt_mult(handle, nil, &curve, &generator, &privateKeyOp)
    if ret != 0 {
        fmt.Printf("ERROR: pka_ecc_pt_mult failed: %d\n", ret)
        return
    }
    
    for !C.pka_has_avail_result(handle) {}
    C.pka_get_result(handle, &keygenResults)
    
    if keygenResults.status != C.RC_NO_ERROR {
        fmt.Printf("ERROR: Key generation failed: %d\n", keygenResults.status)
        return
    }

    // Extract public key
    pubKeyX := C.GoBytes(unsafe.Pointer(C.get_result_x()), 32)
    pubKeyY := C.GoBytes(unsafe.Pointer(C.get_result_y()), 32)
    pubKeyXDisplay := make([]byte, 32)
    pubKeyYDisplay := make([]byte, 32)
    copy(pubKeyXDisplay, pubKeyX)
    copy(pubKeyYDisplay, pubKeyY)
    reverseBytes(pubKeyXDisplay)
    reverseBytes(pubKeyYDisplay)
    
    fmt.Printf("    Private key: %s...\n", hex.EncodeToString(privateKeyDisplay[:16]))
    fmt.Printf("    Public key X: %s...\n", hex.EncodeToString(pubKeyXDisplay[:16]))
    fmt.Printf("    Public key Y: %s...\n", hex.EncodeToString(pubKeyYDisplay[:16]))

    // Setup public key point for verification later
    pubKeyXC := C.alloc_copy(unsafe.Pointer(&pubKeyX[0]), 32)
    pubKeyYC := C.alloc_copy(unsafe.Pointer(&pubKeyY[0]), 32)
    defer C.free(unsafe.Pointer(pubKeyXC))
    defer C.free(unsafe.Pointer(pubKeyYC))
    
    var publicKey C.ecc_point_t
    C.init_operand(&publicKey.x, pubKeyXC, 32, 0)
    C.init_operand(&publicKey.y, pubKeyYC, 32, 0)

    // ========== MESSAGE & HASH ==========
    fmt.Println("\n[3] Hashing message...")
    message := "Hello from Bluefield DPU!"
    hash := sha256.Sum256([]byte(message))
    hashDisplay := make([]byte, 32)
    copy(hashDisplay, hash[:])
    
    // Convert hash to little-endian for PKA
    hashLE := make([]byte, 32)
    copy(hashLE, hash[:])
    reverseBytes(hashLE)
    
    hashC := C.alloc_copy(unsafe.Pointer(&hashLE[0]), 32)
    defer C.free(unsafe.Pointer(hashC))
    
    var hashOp C.pka_operand_t
    C.init_operand(&hashOp, hashC, 32, 0)
    
    fmt.Printf("    Message: \"%s\"\n", message)
    fmt.Printf("    SHA-256: %s\n", hex.EncodeToString(hashDisplay))

    // ========== SIGNING ==========
    fmt.Println("\n[4] Signing with PKA...")
    
    // Generate random k (nonce) - CRITICAL: must have proper entropy
    kGo := make([]byte, 32)
    for {
        _, err := rand.Read(kGo)
        if err != nil {
            fmt.Printf("ERROR: Failed to generate nonce: %v\n", err)
            return
        }
        if !isZero(kGo) {
            break
        }
    }
    reverseBytes(kGo) // Little-endian
    
    kC := C.alloc_copy(unsafe.Pointer(&kGo[0]), 32)
    defer C.free(unsafe.Pointer(kC))
    
    var kOp C.pka_operand_t
    C.init_operand(&kOp, kC, 32, 0)

    // Sign
    var signResults C.pka_results_t
    C.init_sign_results(&signResults)
    
    ret = C.pka_ecdsa_signature_generate(
        handle, nil,
        &curve,
        &generator,
        &order,
        &privateKeyOp,
        &hashOp,
        &kOp,
    )
    if ret != 0 {
        fmt.Printf("ERROR: pka_ecdsa_signature_generate failed: %d\n", ret)
        return
    }

    for !C.pka_has_avail_result(handle) {}
    C.pka_get_result(handle, &signResults)
    
    if signResults.status != C.RC_NO_ERROR {
        fmt.Printf("ERROR: Signing failed with status: %d (0x%x)\n", signResults.status, signResults.status)
        return
    }

    // Extract signature (r, s)
    sigR := C.GoBytes(unsafe.Pointer(C.get_sig_r()), 32)
    sigS := C.GoBytes(unsafe.Pointer(C.get_sig_s()), 32)
    sigRDisplay := make([]byte, 32)
    sigSDisplay := make([]byte, 32)
    copy(sigRDisplay, sigR)
    copy(sigSDisplay, sigS)
    reverseBytes(sigRDisplay)
    reverseBytes(sigSDisplay)
    
    fmt.Printf("    Signature r: %s\n", hex.EncodeToString(sigRDisplay))
    fmt.Printf("    Signature s: %s\n", hex.EncodeToString(sigSDisplay))

    // ========== VERIFICATION ==========
    fmt.Println("\n[5] Verifying signature with PKA...")
    
    // Setup signature for verification
    sigRC := C.alloc_copy(unsafe.Pointer(&sigR[0]), 32)
    sigSC := C.alloc_copy(unsafe.Pointer(&sigS[0]), 32)
    defer C.free(unsafe.Pointer(sigRC))
    defer C.free(unsafe.Pointer(sigSC))
    
    var signature C.dsa_signature_t
    C.init_operand(&signature.r, sigRC, 32, 0)
    C.init_operand(&signature.s, sigSC, 32, 0)

    var verifyResults C.pka_results_t
    C.init_verify_results(&verifyResults)
    
    ret = C.pka_ecdsa_signature_verify(
        handle, nil,
        &curve,
        &generator,
        &order,
        &publicKey,
        &hashOp,
        &signature,
        1, // no_write = 1 (no write-back)
    )
    if ret != 0 {
        fmt.Printf("ERROR: pka_ecdsa_signature_verify call failed: %d\n", ret)
        return
    }

    for !C.pka_has_avail_result(handle) {}
    C.pka_get_result(handle, &verifyResults)

    fmt.Println()
    fmt.Println("=== Results ===")
    if verifyResults.status == C.RC_NO_ERROR {
        fmt.Println("    SIGNATURE VALID!")
    } else {
        fmt.Printf("    SIGNATURE INVALID (status: %d)\n", verifyResults.status)
    }
    fmt.Println()
}
