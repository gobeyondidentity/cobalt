//go:build windows

package dpop

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// makeFileInsecure adds an ACE granting read access to the specified well-known SID.
// This simulates an insecure file for testing by adding a permissive ACE to the DACL.
func makeFileInsecure(path string, sid *windows.SID) error {
	// Get current security descriptor with DACL
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}

	// Get current DACL
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}

	// Create explicit access entry for the insecure SID
	ea := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_READ,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}

	// Create new ACL with the insecure ACE added to existing DACL
	newAcl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{ea}, dacl)
	if err != nil {
		return err
	}

	// Set the new DACL on the file
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil, newAcl, nil,
	)
}

func TestCheckFilePermissions_RejectsEveryone(t *testing.T) {
	t.Log("Testing checkFilePermissions rejects file accessible to Everyone")

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "insecure-everyone.txt")

	t.Log("Creating file with proper permissions first")
	if err := os.WriteFile(testFile, []byte("secret"), 0600); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	if err := setFilePermissions(testFile); err != nil {
		t.Fatalf("failed to set permissions: %v", err)
	}

	t.Log("Adding Everyone ACE to make file insecure")
	if err := makeFileInsecure(testFile, sidEveryone); err != nil {
		t.Fatalf("failed to make file insecure: %v", err)
	}

	t.Log("Checking that insecure file is rejected")
	err := checkFilePermissions(testFile)
	if err == nil {
		t.Fatal("expected error for file accessible to Everyone")
	}
	if !IsPermissionError(err) {
		t.Errorf("expected ErrInvalidPermissions, got: %v", err)
	}
	t.Logf("Correctly rejected: %v", err)
}

func TestCheckFilePermissions_RejectsUsers(t *testing.T) {
	t.Log("Testing checkFilePermissions rejects file accessible to Users group")

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "insecure-users.txt")

	t.Log("Creating file with proper permissions first")
	if err := os.WriteFile(testFile, []byte("secret"), 0600); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	if err := setFilePermissions(testFile); err != nil {
		t.Fatalf("failed to set permissions: %v", err)
	}

	t.Log("Adding Users ACE to make file insecure")
	if err := makeFileInsecure(testFile, sidUsers); err != nil {
		t.Fatalf("failed to make file insecure: %v", err)
	}

	t.Log("Checking that insecure file is rejected")
	err := checkFilePermissions(testFile)
	if err == nil {
		t.Fatal("expected error for file accessible to Users group")
	}
	if !IsPermissionError(err) {
		t.Errorf("expected ErrInvalidPermissions, got: %v", err)
	}
	t.Logf("Correctly rejected: %v", err)
}

func TestCheckFilePermissions_RejectsAuthenticatedUsers(t *testing.T) {
	t.Log("Testing checkFilePermissions rejects file accessible to Authenticated Users")

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "insecure-authusers.txt")

	t.Log("Creating file with proper permissions first")
	if err := os.WriteFile(testFile, []byte("secret"), 0600); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	if err := setFilePermissions(testFile); err != nil {
		t.Fatalf("failed to set permissions: %v", err)
	}

	t.Log("Adding Authenticated Users ACE to make file insecure")
	if err := makeFileInsecure(testFile, sidAuthenticatedUsers); err != nil {
		t.Fatalf("failed to make file insecure: %v", err)
	}

	t.Log("Checking that insecure file is rejected")
	err := checkFilePermissions(testFile)
	if err == nil {
		t.Fatal("expected error for file accessible to Authenticated Users")
	}
	if !IsPermissionError(err) {
		t.Errorf("expected ErrInvalidPermissions, got: %v", err)
	}
	t.Logf("Correctly rejected: %v", err)
}

func TestSetFilePermissions_CreatesRestrictiveDACL(t *testing.T) {
	t.Log("Testing setFilePermissions creates proper restrictive DACL")

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "restricted.txt")

	t.Log("Creating file with default inherited permissions")
	if err := os.WriteFile(testFile, []byte("secret"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	t.Log("Setting restrictive permissions via setFilePermissions")
	if err := setFilePermissions(testFile); err != nil {
		t.Fatalf("failed to set permissions: %v", err)
	}

	t.Log("Verifying file passes permission check")
	if err := checkFilePermissions(testFile); err != nil {
		t.Errorf("expected file to pass permission check after setFilePermissions: %v", err)
	}

	t.Log("setFilePermissions creates properly restricted DACL")
}

func TestSetFilePermissions_RemovesInsecureACEs(t *testing.T) {
	t.Log("Testing setFilePermissions removes insecure ACEs")

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "was-insecure.txt")

	t.Log("Creating file and making it insecure")
	if err := os.WriteFile(testFile, []byte("secret"), 0600); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	if err := makeFileInsecure(testFile, sidEveryone); err != nil {
		t.Fatalf("failed to make file insecure: %v", err)
	}

	t.Log("Verifying file is currently insecure")
	if err := checkFilePermissions(testFile); err == nil {
		t.Fatal("expected file to be insecure before fix")
	}

	t.Log("Applying setFilePermissions to fix the DACL")
	if err := setFilePermissions(testFile); err != nil {
		t.Fatalf("failed to set permissions: %v", err)
	}

	t.Log("Verifying file is now secure")
	if err := checkFilePermissions(testFile); err != nil {
		t.Errorf("expected file to be secure after setFilePermissions: %v", err)
	}

	t.Log("setFilePermissions successfully removed insecure ACEs")
}

func TestCheckFilePermissions_AcceptsSystemAndOwner(t *testing.T) {
	t.Log("Testing checkFilePermissions accepts files with only SYSTEM and owner access")

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "owner-only.txt")

	t.Log("Creating file with proper permissions")
	if err := os.WriteFile(testFile, []byte("secret"), 0600); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	if err := setFilePermissions(testFile); err != nil {
		t.Fatalf("failed to set permissions: %v", err)
	}

	t.Log("Verifying file is accepted")
	if err := checkFilePermissions(testFile); err != nil {
		t.Errorf("expected file to be accepted: %v", err)
	}

	t.Log("File with SYSTEM and owner only is accepted")
}

func TestCheckFilePermissions_RejectsNullDACL(t *testing.T) {
	t.Log("Testing checkFilePermissions rejects file with NULL DACL")

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "null-dacl.txt")

	t.Log("Creating file")
	if err := os.WriteFile(testFile, []byte("secret"), 0600); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	t.Log("Setting NULL DACL (grants full access to everyone)")
	err := windows.SetNamedSecurityInfo(
		testFile,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil, nil, nil, // nil DACL means full access to everyone
	)
	if err != nil {
		t.Fatalf("failed to set NULL DACL: %v", err)
	}

	t.Log("Checking that NULL DACL file is rejected")
	err = checkFilePermissions(testFile)
	if err == nil {
		t.Fatal("expected error for file with NULL DACL")
	}
	if !IsPermissionError(err) {
		t.Errorf("expected ErrInvalidPermissions, got: %v", err)
	}
	t.Logf("Correctly rejected NULL DACL: %v", err)
}

// verifyDACL is a helper that dumps the DACL for debugging.
// Useful during test development.
func verifyDACL(t *testing.T, path string) {
	t.Helper()

	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Logf("failed to get security info: %v", err)
		return
	}

	owner, _, err := sd.Owner()
	if err != nil {
		t.Logf("failed to get owner: %v", err)
	} else {
		t.Logf("Owner: %s", owner.String())
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		t.Logf("failed to get DACL: %v", err)
		return
	}
	if dacl == nil {
		t.Log("DACL is NULL (full access to everyone)")
		return
	}

	t.Logf("DACL has %d ACEs", dacl.AceCount)
	for i := 0; i < int(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := getAce(dacl, uint32(i), &ace); err != nil {
			t.Logf("  ACE %d: error getting ACE: %v", i, err)
			continue
		}
		aceSid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		t.Logf("  ACE %d: SID=%s Mask=0x%08x", i, aceSid.String(), ace.Mask)
	}
}
