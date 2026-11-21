package authenticode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogSignedSystemBinary(t *testing.T) {
	r := Verify(filepath.Join(os.Getenv("SystemRoot"), `System32\cmd.exe`))
	if !r.Valid || !strings.Contains(r.Signer, "Microsoft") {
		t.Fatalf("cmd.exe: got %+v, want valid Microsoft signature", r)
	}
}

func TestUnsignedTestBinary(t *testing.T) {
	exe, _ := os.Executable() // go test binaries are unsigned
	r := Verify(exe)
	if r.Signed || r.Valid {
		t.Fatalf("test binary: got %+v, want unsigned", r)
	}
}

func TestTamperedCopyIsNotValid(t *testing.T) {
	src := filepath.Join(os.Getenv("SystemRoot"), `System32\cmd.exe`)
	b, err := os.ReadFile(src)
	if err != nil {
		t.Skip(err)
	}
	// A renamed copy outside System32 is still catalog-valid (same hash)…
	dir := t.TempDir()
	cp := filepath.Join(dir, "MsMpEng.exe")
	os.WriteFile(cp, b, 0o644)
	if r := Verify(cp); !r.Valid {
		t.Fatalf("identical copy should still verify: %+v", r)
	}
	// …but one flipped byte must not be.
	b[len(b)/2] ^= 0xff
	bad := filepath.Join(dir, "evil.exe")
	os.WriteFile(bad, b, 0o644)
	if r := Verify(bad); r.Valid {
		t.Fatalf("tampered copy verified: %+v", r)
	}
}
