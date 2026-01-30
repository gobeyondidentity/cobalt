//go:build windows

package dpop

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Well-known SIDs that indicate overly permissive access
var (
	// S-1-1-0: Everyone
	sidEveryone *windows.SID
	// S-1-5-32-545: Users
	sidUsers *windows.SID
	// S-1-5-11: Authenticated Users
	sidAuthenticatedUsers *windows.SID
	// S-1-5-18: Local System
	sidSystem *windows.SID
)

func init() {
	var err error
	sidEveryone, err = windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		panic("failed to create Everyone SID: " + err.Error())
	}
	sidUsers, err = windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		panic("failed to create Users SID: " + err.Error())
	}
	sidAuthenticatedUsers, err = windows.CreateWellKnownSid(windows.WinAuthenticatedUserSid)
	if err != nil {
		panic("failed to create Authenticated Users SID: " + err.Error())
	}
	sidSystem, err = windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		panic("failed to create SYSTEM SID: " + err.Error())
	}
}

// checkFilePermissions verifies a file has owner-only access on Windows.
// Returns ErrInvalidPermissions if Everyone, Users, or Authenticated Users have access.
func checkFilePermissions(path string) error {
	// Get security descriptor with DACL and owner info
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("get security info: %w", err)
	}

	// Get the DACL from the security descriptor
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("get DACL: %w", err)
	}
	if dacl == nil {
		// NULL DACL means full access to everyone
		return fmt.Errorf("%w: file has no DACL (full access to everyone)", ErrInvalidPermissions)
	}

	// Get owner SID for comparison
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("get owner: %w", err)
	}

	// Iterate through ACEs in the DACL
	aceCount := int(dacl.AceCount)
	for i := 0; i < aceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := getAce(dacl, uint32(i), &ace); err != nil {
			return fmt.Errorf("get ACE %d: %w", i, err)
		}

		// Get the SID from the ACE
		aceSid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))

		// Skip if this is the owner or SYSTEM
		if aceSid.Equals(owner) || aceSid.Equals(sidSystem) {
			continue
		}

		// Check for overly permissive SIDs
		if aceSid.Equals(sidEveryone) {
			return fmt.Errorf("%w: file accessible to Everyone", ErrInvalidPermissions)
		}
		if aceSid.Equals(sidUsers) {
			return fmt.Errorf("%w: file accessible to Users group", ErrInvalidPermissions)
		}
		if aceSid.Equals(sidAuthenticatedUsers) {
			return fmt.Errorf("%w: file accessible to Authenticated Users", ErrInvalidPermissions)
		}

		// Any other SID besides owner/SYSTEM is suspicious
		sidStr := aceSid.String()
		return fmt.Errorf("%w: file accessible to other user (%s)", ErrInvalidPermissions, sidStr)
	}

	return nil
}

// setFilePermissions sets owner-only access on Windows.
// Creates a DACL with only the owner and SYSTEM having access.
func setFilePermissions(path string) error {
	// Get current owner
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("get owner info: %w", err)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("get owner SID: %w", err)
	}

	// Build explicit access entries for owner and SYSTEM
	ea := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_READ | windows.GENERIC_WRITE | windows.DELETE,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(owner),
			},
		},
		{
			AccessPermissions: windows.GENERIC_READ | windows.GENERIC_WRITE | windows.DELETE,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(sidSystem),
			},
		},
	}

	// Create new ACL from explicit access entries
	acl, err := windows.ACLFromEntries(ea, nil)
	if err != nil {
		return fmt.Errorf("create ACL: %w", err)
	}

	// Set the new DACL with protection (no inheritance)
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	)
	if err != nil {
		return fmt.Errorf("set security info: %w", err)
	}

	return nil
}

// getAce retrieves an ACE from an ACL by index.
// This wraps the Windows GetAce function.
func getAce(acl *windows.ACL, index uint32, ace **windows.ACCESS_ALLOWED_ACE) error {
	ret, _, err := syscall.SyscallN(
		procGetAce.Addr(),
		uintptr(unsafe.Pointer(acl)),
		uintptr(index),
		uintptr(unsafe.Pointer(ace)),
	)
	if ret == 0 {
		return err
	}
	return nil
}

var (
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	procGetAce  = modadvapi32.NewProc("GetAce")
)

// Ensure file exists before checking permissions
func init() {
	// Verify advapi32.dll loads correctly
	if err := modadvapi32.Load(); err != nil {
		// This should never happen on Windows
		panic("failed to load advapi32.dll: " + err.Error())
	}
}

// For files that don't exist yet, we skip permission check
// The file will be created with proper permissions by setFilePermissions
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
