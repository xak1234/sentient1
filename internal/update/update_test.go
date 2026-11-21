package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		cur, tag string
		want     bool
	}{
		{"v0.1.0", "v0.2.0", true},
		{"v0.2.0", "v0.2.0", false},
		{"v0.2.0", "v0.1.9", false}, // never downgrade
		{"v0.9.0", "v0.10.0", true}, // numeric, not lexical
		{"v1.0.0", "v0.99.99", false},
		{"dev", "v9.9.9", false},        // dev builds never update
		{"ci-abc123", "v9.9.9", false},  // CI builds never update
		{"v0.1.0", "v0.2.0-rc1", false}, // pre-releases are ignored
		{"v0.1.0", "garbage", false},
	}
	for _, c := range cases {
		if got := Newer(c.cur, c.tag); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", c.cur, c.tag, got, c.want)
		}
	}
}

func TestLookup(t *testing.T) {
	sums := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789ABCDEF  sentient1_v1.0.0_windows_amd64.exe\n" +
		"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210  sentient1_v1.0.0_windows_arm64.exe\n"
	h, err := lookup([]byte(sums), "sentient1_v1.0.0_windows_amd64.exe")
	if err != nil || h != strings.ToLower("0123456789abcdef0123456789abcdef0123456789abcdef0123456789ABCDEF") {
		t.Fatalf("lookup = %q, %v", h, err)
	}
	if _, err := lookup([]byte(sums), "sentient1_v1.0.0_windows_386.exe"); err == nil {
		t.Fatal("expected a missing asset to be an error")
	}
	// a name that's only a suffix of a listed file must not match
	if _, err := lookup([]byte(sums), "windows_amd64.exe"); err == nil {
		t.Fatal("suffix matched")
	}
}

func TestVerifySignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	old := PublicKey
	PublicKey = base64.StdEncoding.EncodeToString(pub)
	defer func() { PublicKey = old }()

	msg := []byte("abc  sentient1_v1.0.0_windows_amd64.exe\n")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)) + "\n"
	if err := VerifySignature(msg, []byte(sig)); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	tampered := append([]byte(nil), msg...)
	tampered[0] = 'x'
	if err := VerifySignature(tampered, []byte(sig)); err == nil {
		t.Fatal("tampered checksum list accepted")
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifySignature(msg, []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(other, msg)))); err == nil {
		t.Fatal("signature from another key accepted")
	}
	if err := VerifySignature(msg, []byte("not base64!")); err == nil {
		t.Fatal("garbage signature accepted")
	}
}

func TestNoUpstreamUpdateAuthority(t *testing.T) {
	if Repo != "" || API != "" || PublicKey != "" || Enabled() {
		t.Fatal("sentient1 must not inherit upstream update authority")
	}
	if _, err := Latest(t.Context()); err == nil {
		t.Fatal("unconfigured release channel was accepted")
	}
}

func TestUntrustedHostsRefused(t *testing.T) {
	for _, u := range []string{"http://github.com/x", "https://evil.example/x", "https://github.com.evil.example/x", "file:///C:/x.exe"} {
		if _, err := get(t.Context(), u, 10); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Errorf("get(%q) not refused: %v", u, err)
		}
	}
}

func TestDownloadRefusesUnsigned(t *testing.T) {
	r := &Release{Tag: "v9.9.9", Assets: []Asset{
		{Name: AssetName("v9.9.9"), URL: "https://github.com/x"},
		{Name: "SHA256SUMS.txt", URL: "https://github.com/y"},
	}}
	if _, err := Download(t.Context(), r, t.TempDir()); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("unsigned release not refused: %v", err)
	}
	r.Prerelease = true
	if _, err := Download(t.Context(), r, t.TempDir()); err == nil {
		t.Fatal("pre-release not refused")
	}
}
