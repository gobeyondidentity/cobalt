package main

/*
#cgo LDFLAGS: -lPKA
#include <pka.h>
*/
import "C"
import "fmt"

func main() {
    fmt.Println("=== PKA CGO Test ===")
    fmt.Println()
    
    // Initialize PKA global instance
    // Using reasonable defaults: 1 ring, 1 queue, 4KB queue sizes
    fmt.Println("[1] Initializing PKA global instance...")
    instance := C.pka_init_global(
        C.CString("go-pka-test"),
        C.PKA_F_PROCESS_MODE_SINGLE | C.PKA_F_SYNC_MODE_ENABLE,
        1,     // ring_cnt
        1,     // queue_cnt  
        4096,  // cmd_queue_size
        4096,  // result_queue_size
    )
    
    if instance == C.PKA_INSTANCE_INVALID {
        fmt.Println("ERROR: pka_init_global failed")
        return
    }
    fmt.Println("   pka_init_global: SUCCESS")
    fmt.Printf("   Instance handle: %d\n", instance)
    
    // Initialize local handle
    fmt.Println("[2] Initializing PKA local handle...")
    handle := C.pka_init_local(instance)
    if handle == nil {
        fmt.Println("ERROR: pka_init_local failed")
        C.pka_term_global(instance)
        return
    }
    fmt.Println("   pka_init_local: SUCCESS")
    
    // Get byte order
    byteOrder := C.pka_get_rings_byte_order(handle)
    fmt.Printf("   Ring byte order: %d (0=little, 1=big)\n", byteOrder)
    
    // Clean up
    fmt.Println("[3] Cleaning up...")
    C.pka_term_local(handle)
    C.pka_term_global(instance)
    fmt.Println("   Cleanup: SUCCESS")
    
    fmt.Println()
    fmt.Println("=== PKA library access VALIDATED ===")
}
