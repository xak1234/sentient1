// Package authenticode verifies Windows code signatures (embedded and
// catalog-signed) and extracts the signer's name.
package authenticode

import (
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Result of a signature check.
type Result struct {
	Signed  bool   `json:"signed"`           // has a signature at all
	Valid   bool   `json:"valid"`            // chain + hash verified
	Signer  string `json:"signer,omitempty"` // subject simple display name
	Catalog bool   `json:"catalog,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (r Result) String() string {
	switch {
	case r.Valid:
		s := "signed by " + r.Signer
		if r.Catalog {
			s += " (catalog)"
		}
		return s
	case r.Signed:
		return "INVALID signature (" + r.Error + ")"
	}
	return "unsigned"
}

var (
	wintrust                                 = windows.NewLazySystemDLL("wintrust.dll")
	procWTHelperProvDataFromStateData        = wintrust.NewProc("WTHelperProvDataFromStateData")
	procWTHelperGetProvSignerFromChain       = wintrust.NewProc("WTHelperGetProvSignerFromChain")
	procWTHelperGetProvCertFromChain         = wintrust.NewProc("WTHelperGetProvCertFromChain")
	procCryptCATAdminAcquireContext2         = wintrust.NewProc("CryptCATAdminAcquireContext2")
	procCryptCATAdminReleaseContext          = wintrust.NewProc("CryptCATAdminReleaseContext")
	procCryptCATAdminCalcHashFromFileHandle2 = wintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	procCryptCATAdminEnumCatalogFromHash     = wintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCryptCATCatalogInfoFromContext       = wintrust.NewProc("CryptCATCatalogInfoFromContext")
	procCryptCATAdminReleaseCatalogContext   = wintrust.NewProc("CryptCATAdminReleaseCatalogContext")
)

const (
	trustENoSignature        = 0x800B0100
	trustESubjectFormUnknown = 0x800B0003
	trustEProviderUnknown    = 0x800B0001
	certNameSimpleDisplay    = 4
)

type cryptProviderCert struct {
	Size uint32
	Cert *windows.CertContext
}

type catalogInfo struct {
	Size        uint32
	CatalogFile [windows.MAX_PATH]uint16
}

type wintrustCatalogInfo struct {
	Size                 uint32
	CatalogVersion       uint32
	CatalogFilePath      *uint16
	MemberTag            *uint16
	MemberFilePath       *uint16
	MemberFile           windows.Handle
	CalculatedFileHash   *byte
	CalculatedFileHashSz uint32
	CatalogContext       uintptr
	CatAdmin             uintptr
}

type cacheEntry struct {
	res Result
	at  time.Time
}

var (
	cacheMu sync.Mutex
	cache   = map[string]cacheEntry{}
)

// Verify checks path, trying the embedded signature first and then the system
// catalogs. Results are cached for 10 minutes per path.
func Verify(path string) Result {
	key := strings.ToLower(path)
	cacheMu.Lock()
	if e, ok := cache[key]; ok && time.Since(e.at) < 10*time.Minute {
		cacheMu.Unlock()
		return e.res
	}
	cacheMu.Unlock()

	res := verifyEmbedded(path)
	if !res.Signed {
		if cr, ok := verifyCatalog(path); ok {
			res = cr
		}
	}
	cacheMu.Lock()
	cache[key] = cacheEntry{res, time.Now()}
	cacheMu.Unlock()
	return res
}

func verifyEmbedded(path string) Result {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return Result{Error: err.Error()}
	}
	fi := windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: p}
	return runWinTrust(windows.WTD_CHOICE_FILE, unsafe.Pointer(&fi), false)
}

func runWinTrust(choice uint32, info unsafe.Pointer, catalog bool) Result {
	data := windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE, // offline-safe; we may be isolated
		UnionChoice:                     choice,
		FileOrCatalogOrBlobOrSgnrOrCert: info,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       windows.WTD_CACHE_ONLY_URL_RETRIEVAL | windows.WTD_REVOCATION_CHECK_NONE,
	}
	err := windows.WinVerifyTrustEx(windows.HWND(windows.InvalidHandle), &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	res := Result{Catalog: catalog}
	var code uint32
	if err != nil {
		var errno windows.Errno
		if errors.As(err, &errno) {
			code = uint32(errno)
		}
	}
	switch {
	case err == nil:
		res.Signed, res.Valid = true, true
	case code == trustENoSignature || code == trustESubjectFormUnknown || code == trustEProviderUnknown:
		res.Signed = false
	default:
		res.Signed = true
		res.Error = err.Error()
	}
	if res.Signed && data.StateData != 0 {
		res.Signer = signerName(data.StateData)
	}
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	windows.WinVerifyTrustEx(windows.HWND(windows.InvalidHandle), &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	return res
}

func signerName(state windows.Handle) string {
	prov, _, _ := procWTHelperProvDataFromStateData.Call(uintptr(state))
	if prov == 0 {
		return ""
	}
	sgnr, _, _ := procWTHelperGetProvSignerFromChain.Call(prov, 0, 0, 0)
	if sgnr == 0 {
		return ""
	}
	pc, _, _ := procWTHelperGetProvCertFromChain.Call(sgnr, 0)
	if pc == 0 {
		return ""
	}
	cert := (*(**cryptProviderCert)(unsafe.Pointer(&pc))).Cert // OS-owned memory
	if cert == nil {
		return ""
	}
	buf := make([]uint16, 256)
	n := windows.CertGetNameString(cert, certNameSimpleDisplay, 0, nil, &buf[0], uint32(len(buf)))
	if n <= 1 {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// verifyCatalog looks the file's hash up in the system catalogs (how most
// in-box Windows binaries are signed). ok=false if no catalog contains it.
func verifyCatalog(path string) (Result, bool) {
	f, err := windows.Open(path, windows.O_RDONLY, 0)
	if err != nil {
		return Result{}, false
	}
	defer windows.CloseHandle(f)
	p, _ := windows.UTF16PtrFromString(path)

	for _, alg := range []string{"SHA256", "SHA1"} {
		algp, _ := windows.UTF16PtrFromString(alg)
		var admin uintptr
		if r, _, _ := procCryptCATAdminAcquireContext2.Call(uintptr(unsafe.Pointer(&admin)), 0, uintptr(unsafe.Pointer(algp)), 0, 0); r == 0 {
			continue
		}
		res, ok := func() (Result, bool) {
			defer procCryptCATAdminReleaseContext.Call(admin, 0)
			var size uint32 = 64
			hash := make([]byte, size)
			if r, _, _ := procCryptCATAdminCalcHashFromFileHandle2.Call(admin, uintptr(f), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&hash[0])), 0); r == 0 {
				return Result{}, false
			}
			hash = hash[:size]
			catCtx, _, _ := procCryptCATAdminEnumCatalogFromHash.Call(admin, uintptr(unsafe.Pointer(&hash[0])), uintptr(size), 0, 0)
			if catCtx == 0 {
				return Result{}, false
			}
			defer procCryptCATAdminReleaseCatalogContext.Call(admin, catCtx, 0)
			ci := catalogInfo{Size: uint32(unsafe.Sizeof(catalogInfo{}))}
			if r, _, _ := procCryptCATCatalogInfoFromContext.Call(catCtx, uintptr(unsafe.Pointer(&ci)), 0); r == 0 {
				return Result{}, false
			}
			tag, _ := windows.UTF16PtrFromString(strings.ToUpper(hex.EncodeToString(hash)))
			wci := wintrustCatalogInfo{
				Size:                 uint32(unsafe.Sizeof(wintrustCatalogInfo{})),
				CatalogFilePath:      &ci.CatalogFile[0],
				MemberTag:            tag,
				MemberFilePath:       p,
				MemberFile:           f,
				CalculatedFileHash:   &hash[0],
				CalculatedFileHashSz: size,
				CatAdmin:             admin,
			}
			r := runWinTrust(windows.WTD_CHOICE_CATALOG, unsafe.Pointer(&wci), true)
			return r, r.Signed
		}()
		if ok {
			return res, true
		}
	}
	return Result{}, false
}
