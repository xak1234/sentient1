// Package winsec wraps the Windows security plumbing SENTIENT1 relies on:
// privileges, elevation, file audit rules (SACLs) and the system audit policy.
package winsec

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// IsElevated reports whether the current process runs with an elevated admin token.
func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// EnablePrivilege turns on a privilege in the current process token.
func EnablePrivilege(name string) error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close()
	var luid windows.LUID
	n, _ := windows.UTF16PtrFromString(name)
	if err := windows.LookupPrivilegeValue(nil, n, &luid); err != nil {
		return err
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	// Call directly so the last error is captured atomically: the API "succeeds"
	// with ERROR_NOT_ALL_ASSIGNED when we don't hold the privilege.
	r, _, e := procAdjustTokenPrivileges.Call(uintptr(tok), 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
	if r == 0 {
		return fmt.Errorf("AdjustTokenPrivileges: %w", e)
	}
	if errors.Is(e, windows.ERROR_NOT_ALL_ASSIGNED) {
		return fmt.Errorf("privilege %s not held (run as administrator)", name)
	}
	return nil
}

const (
	SeSecurityPrivilege = "SeSecurityPrivilege"
	SeDebugPrivilege    = "SeDebugPrivilege"

	fileReadData = 0x0001
	accessDelete = 0x00010000

	// BaitAuditMask is what we audit on baits: reading content, and deletion/rename.
	BaitAuditMask = fileReadData | accessDelete
)

// AccessMaskIsRead / IsDelete interpret 4663 access masks.
func AccessMaskIsRead(mask uint32) bool   { return mask&fileReadData != 0 }
func AccessMaskIsDelete(mask uint32) bool { return mask&accessDelete != 0 }

// SetBaitAudit replaces the file's SACL with "audit successful ReadData and
// DELETE by Everyone". Requires SeSecurityPrivilege (admin). Malware running as
// the user can neither see nor remove this rule.
func SetBaitAudit(path string) error {
	if err := EnablePrivilege(SeSecurityPrivilege); err != nil {
		return err
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return err
	}
	sacl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: BaitAuditMask,
		AccessMode:        windows.SET_AUDIT_SUCCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}}, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.SACL_SECURITY_INFORMATION|windows.PROTECTED_SACL_SECURITY_INFORMATION, nil, nil, nil, sacl)
}

// ClearAudit removes all audit entries from the file's SACL.
func ClearAudit(path string) error {
	if err := EnablePrivilege(SeSecurityPrivilege); err != nil {
		return err
	}
	// ACLFromEntries(nil, nil) dereferences a NULL ACL, so build an empty one
	// by hand: an 8-byte header with revision 2 and zero entries.
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.SACL_SECURITY_INFORMATION|windows.UNPROTECTED_SACL_SECURITY_INFORMATION, nil, nil, nil, EmptyACL())
}

// HasBaitAudit reports whether the file's SACL still audits ReadData.
func HasBaitAudit(path string) (bool, error) {
	if err := EnablePrivilege(SeSecurityPrivilege); err != nil {
		return false, err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.SACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	sacl, _, err := sd.SACL()
	if err != nil || sacl == nil {
		return false, nil
	}
	n := aclAceCount(sacl)
	for i := uint32(0); i < n; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE // SYSTEM_AUDIT_ACE has the same layout
		if err := windows.GetAce(sacl, i, &ace); err != nil {
			continue
		}
		const systemAuditAceType = 2
		if ace.Header.AceType == systemAuditAceType && uint32(ace.Mask)&fileReadData != 0 {
			return true, nil
		}
	}
	return false, nil
}

func aclAceCount(acl *windows.ACL) uint32 {
	// ACL header: AclRevision(1) Sbz1(1) AclSize(2) AceCount(2) Sbz2(2)
	return uint32(*(*uint16)(unsafe.Add(unsafe.Pointer(acl), 4)))
}

// ---- System audit policy ("Audit File System" subcategory) ----

// FileSystemAuditGUID is the locale-independent "File System" subcategory.
var FileSystemAuditGUID = windows.GUID{Data1: 0x0CCE921D, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}

const (
	AuditSuccess = 0x1
	AuditFailure = 0x2
	auditNone    = 0x4
)

type auditPolicyInformation struct {
	SubCategory windows.GUID
	Info        uint32
	Category    windows.GUID
}

var (
	advapi                     = windows.NewLazySystemDLL("advapi32.dll")
	procAdjustTokenPrivileges  = advapi.NewProc("AdjustTokenPrivileges")
	procAuditQuerySystemPolicy = advapi.NewProc("AuditQuerySystemPolicy")
	procAuditSetSystemPolicy   = advapi.NewProc("AuditSetSystemPolicy")
	procAuditFree              = advapi.NewProc("AuditFree")
)

// FileSystemAudit returns the current flags (AuditSuccess|AuditFailure).
func FileSystemAudit() (uint32, error) {
	if err := EnablePrivilege(SeSecurityPrivilege); err != nil {
		return 0, err
	}
	var out *auditPolicyInformation
	g := FileSystemAuditGUID
	r, _, e := procAuditQuerySystemPolicy.Call(uintptr(unsafe.Pointer(&g)), 1, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return 0, fmt.Errorf("AuditQuerySystemPolicy: %w", e)
	}
	defer procAuditFree.Call(uintptr(unsafe.Pointer(out)))
	return out.Info & (AuditSuccess | AuditFailure), nil
}

// SetFileSystemAudit sets the "File System" subcategory flags exactly.
func SetFileSystemAudit(flags uint32) error {
	if err := EnablePrivilege(SeSecurityPrivilege); err != nil {
		return err
	}
	info := flags & (AuditSuccess | AuditFailure)
	if info == 0 {
		info = auditNone
	}
	p := auditPolicyInformation{SubCategory: FileSystemAuditGUID, Info: info}
	r, _, e := procAuditSetSystemPolicy.Call(uintptr(unsafe.Pointer(&p)), 1)
	if r == 0 {
		return fmt.Errorf("AuditSetSystemPolicy: %w", e)
	}
	return nil
}

// EnsureFileSystemAudit turns on success auditing, preserving failure auditing.
// It returns whether it had to change anything.
func EnsureFileSystemAudit() (changed bool, err error) {
	cur, err := FileSystemAudit()
	if err != nil {
		return false, err
	}
	if cur&AuditSuccess != 0 {
		return false, nil
	}
	return true, SetFileSystemAudit(cur | AuditSuccess)
}

// CurrentUserSID returns the SID string of the current process user.
func CurrentUserSID() (string, string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", "", err
	}
	account, domain, _, err := u.User.Sid.LookupAccount("")
	name := account
	if err == nil && domain != "" {
		name = domain + `\` + account
	}
	return u.User.Sid.String(), name, nil
}

// EmptyACL returns a valid ACL with no entries.
func EmptyACL() *windows.ACL {
	b := make([]uint64, 1) // 8 bytes, 8-aligned
	hdr := (*[8]byte)(unsafe.Pointer(&b[0]))
	hdr[0] = 2                              // ACL_REVISION
	*(*uint16)(unsafe.Pointer(&hdr[2])) = 8 // AclSize
	return (*windows.ACL)(unsafe.Pointer(&b[0]))
}
