// Package update finds, verifies and installs new SENTIENT1 releases.
//
// Trust chain: a release's SHA256SUMS.txt must carry a valid ed25519
// signature (SHA256SUMS.txt.sig) from the release key whose public half is
// compiled into this binary. Only then is the exe's SHA-256 checked against
// the signed list. A compromised download host, a swapped release asset or a
// TLS-intercepting proxy can't get code installed without the private key.
package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	Repo      = ""
	userAgent = "sentient1-updater"
	maxExe    = 200 << 20
	maxSmall  = 1 << 20
)

// PublicKey verifies release signatures (base64 ed25519). The private half
// signs SHA256SUMS.txt in the release workflow.
var PublicKey = ""

// API is the releases endpoint (overridable in tests).
var API = ""

// Enabled requires a sentient1 release endpoint and its independent signing key.
func Enabled() bool {
	key, err := base64.StdEncoding.DecodeString(PublicKey)
	return Repo != "" && API != "" && err == nil && len(key) == ed25519.PublicKeySize
}

var client = &http.Client{Timeout: 5 * time.Minute}

type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

type Release struct {
	Tag        string  `json:"tag_name"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	HTMLURL    string  `json:"html_url"`
	Assets     []Asset `json:"assets"`
}

func (r *Release) asset(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return Asset{}, false
}

// AssetName is the release file for this PC's architecture.
func AssetName(tag string) string {
	return fmt.Sprintf("sentient1_%s_windows_%s.exe", tag, runtime.GOARCH)
}

// Latest asks GitHub for the newest published release.
func Latest(ctx context.Context) (*Release, error) {
	if !Enabled() {
		return nil, errors.New("signed updates are not configured for this sentient1 build; use a verified local release")
	}
	b, err := get(ctx, API, maxSmall)
	if err != nil {
		return nil, fmt.Errorf("check for updates: %w", err)
	}
	var r Release
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("check for updates: %w", err)
	}
	if r.Tag == "" {
		return nil, errors.New("check for updates: no release found")
	}
	return &r, nil
}

// Newer reports whether release tag is newer than the running version.
// Dev/CI builds and anything that isn't plain vX.Y.Z never update.
func Newer(current, tag string) bool {
	c, ok1 := parse(current)
	t, ok2 := parse(tag)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < 3; i++ {
		if t[i] != c[i] {
			return t[i] > c[i]
		}
	}
	return false
}

// Updatable reports whether this build can update itself at all.
func Updatable(current string) bool { _, ok := parse(current); return ok }

func parse(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// Download fetches the release exe for this PC into dir, after verifying the
// signed checksum list. It returns the path of the verified file.
func Download(ctx context.Context, r *Release, dir string) (string, error) {
	if r.Draft || r.Prerelease {
		return "", errors.New("refusing a draft or pre-release")
	}
	name := AssetName(r.Tag)
	exe, ok := r.asset(name)
	if !ok {
		return "", fmt.Errorf("release %s has no %s", r.Tag, name)
	}
	sumsA, ok1 := r.asset("SHA256SUMS.txt")
	sigA, ok2 := r.asset("SHA256SUMS.txt.sig")
	if !ok1 || !ok2 {
		return "", fmt.Errorf("release %s is not signed (no SHA256SUMS.txt.sig)", r.Tag)
	}
	sums, err := get(ctx, sumsA.URL, maxSmall)
	if err != nil {
		return "", err
	}
	sig, err := get(ctx, sigA.URL, maxSmall)
	if err != nil {
		return "", err
	}
	if err := VerifySignature(sums, sig); err != nil {
		return "", err
	}
	want, err := lookup(sums, name)
	if err != nil {
		return "", err
	}
	body, err := get(ctx, exe.URL, maxExe)
	if err != nil {
		return "", err
	}
	got := sha256.Sum256(body)
	if !strings.EqualFold(hex.EncodeToString(got[:]), want) {
		return "", fmt.Errorf("%s: checksum mismatch, not installing", name)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	out := filepath.Join(dir, "sentient1-"+r.Tag+".exe")
	tmp := out + ".part"
	if err := os.WriteFile(tmp, body, 0o755); err != nil {
		return "", err
	}
	os.Remove(out)
	if err := os.Rename(tmp, out); err != nil {
		return "", err
	}
	return out, nil
}

// VerifySignature checks sig (base64 ed25519, optional trailing newline) over msg.
func VerifySignature(msg, sig []byte) error {
	pub, err := base64.StdEncoding.DecodeString(PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("bad built-in release key")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return errors.New("release signature is malformed")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, raw) {
		return errors.New("release signature is INVALID: not installing")
	}
	return nil
}

// lookup finds name's hash in a sha256sum-style list ("<hex>  <name>").
func lookup(sums []byte, name string) (string, error) {
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("%s is not in the signed checksum list", name)
}

func get(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || !trustedHost(u.Host) {
		return nil, fmt.Errorf("refusing to download from %q", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/vnd.github+json, application/octet-stream")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", u.Path, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: response too large", u.Path)
	}
	return b, nil
}

// TrustedHosts are where release metadata and assets may come from. GitHub
// redirects asset downloads to its CDN; the http client follows redirects,
// and the signature check is what actually decides trust.
var TrustedHosts = []string{"api.github.com", "github.com"}

func trustedHost(h string) bool {
	h = strings.ToLower(h)
	for _, t := range TrustedHosts {
		if h == t {
			return true
		}
	}
	return false
}
