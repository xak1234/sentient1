package baits

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/paths"
)

func testUser(t *testing.T) config.UserInfo {
	root := t.TempDir()
	// Isolate from the real machine: markers under Program Files must not leak in.
	t.Setenv("ProgramW6432", filepath.Join(root, "pf"))
	t.Setenv("ProgramFiles", filepath.Join(root, "pf"))
	t.Setenv("ProgramFiles(x86)", filepath.Join(root, "pf86"))
	u := config.UserInfo{
		Profile:        filepath.Join(root, "bob"),
		Desktop:        filepath.Join(root, "bob", "Desktop"),
		Documents:      filepath.Join(root, "bob", "Documents"),
		LocalAppData:   filepath.Join(root, "bob", "AppData", "Local"),
		RoamingAppData: filepath.Join(root, "bob", "AppData", "Roaming"),
	}
	for _, d := range []string{u.Desktop, u.Documents, u.LocalAppData, u.RoamingAppData} {
		os.MkdirAll(d, 0o755)
	}
	return u
}

func TestPlan(t *testing.T) {
	u := testUser(t)
	// Pretend Discord is installed and Exodus was used before.
	os.MkdirAll(filepath.Join(u.LocalAppData, "Discord"), 0o755)
	os.WriteFile(filepath.Join(u.LocalAppData, "Discord", "Update.exe"), nil, 0o644)
	os.MkdirAll(filepath.Join(u.RoamingAppData, "Exodus"), 0o755)

	got := map[string]Availability{}
	for _, a := range Plan(u, nil) {
		got[a.Spec.ID] = a
	}
	if got["discord"].Available || !strings.Contains(got["discord"].Reason, "installed") {
		t.Errorf("discord should be unavailable: %+v", got["discord"])
	}
	if got["exodus"].Available {
		t.Errorf("exodus should be unavailable (data folder exists)")
	}
	for _, id := range []string{"brave", "metamask", "telegram", "desktop-passwords", "keepass", "aws"} {
		if !got[id].Available {
			t.Errorf("%s should be available: %+v", id, got[id])
		}
	}
	// Our own decoy folder existing must not count as "installed".
	os.MkdirAll(filepath.Join(u.LocalAppData, `BraveSoftware\Brave-Browser`), 0o755)
	for _, a := range Plan(u, map[string]bool{"brave": true}) {
		if a.Spec.ID == "brave" && !a.Available {
			t.Errorf("brave decoy we created reported unavailable: %s", a.Reason)
		}
	}
}

func TestGeneratorsProduceTemptingContent(t *testing.T) {
	g := NewGen()
	g.Canary["aws_keys"] = map[string]string{"id": "AKIATESTCANARY000001", "secret": "s3cr3t"}
	if s := string(genPasswordsTxt(g)); !strings.Contains(s, g.Email) || strings.Count(s, "/") < 5 {
		t.Errorf("passwords.txt: %q", s)
	}
	if s := string(genAWSCredentials(g)); !strings.Contains(s, "AKIATESTCANARY000001") {
		t.Errorf("aws creds should use canary keys: %q", s)
	}
	db := genEmptySQLite(g)
	if len(db) != 4096 || !bytes.HasPrefix(db, []byte("SQLite format 3\x00")) || db[100] != 0x0D {
		t.Errorf("sqlite header wrong")
	}
	if k := genKdbx(g); !bytes.HasPrefix(k, []byte{0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5}) {
		t.Errorf("kdbx magic wrong: % x", k[:8])
	}
	// Persona survives a round trip so repairs stay consistent.
	if g2 := GenFromPersona(g.Persona()); g2.Email != g.Email || g2.Year != g.Year {
		t.Errorf("persona round trip: %+v vs %+v", g2, g)
	}
}

func TestEverySpecHasFiles(t *testing.T) {
	u := testUser(t)
	ids := map[string]bool{}
	for _, s := range Catalog {
		if ids[s.ID] {
			t.Errorf("duplicate id %s", s.ID)
		}
		ids[s.ID] = true
		fs := s.Files(u)
		audited := 0
		for _, f := range fs {
			if f.Gen == nil || f.Path == "" {
				t.Errorf("%s: incomplete file spec %+v", s.ID, f)
			}
			if f.Audit {
				audited++
			}
		}
		if audited == 0 {
			t.Errorf("%s: no audited file, it could never trip", s.ID)
		}
		for _, r := range s.RequiresAny {
			if !ids[r] {
				t.Errorf("%s requires %s which must come earlier in the catalog", s.ID, r)
			}
		}
	}
}

// makeShortcut creates a real .lnk with Windows' own shell, like Explorer does.
func makeShortcut(t *testing.T, lnk, target string) {
	t.Helper()
	script := "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('" + lnk + "'); $s.TargetPath='" + target + "'; $s.Save()"
	if out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput(); err != nil {
		t.Skipf("can't create shortcuts here: %v %s", err, out)
	}
}

// The Copilot false alarm came from a Recent-files shortcut to a bait:
// CleanRecent must find and delete exactly those, and nothing else.
func TestCleanRecentRemovesOnlyBaitShortcuts(t *testing.T) {
	root := t.TempDir()
	bait := filepath.Join(root, "Desktop", "passwords.txt")
	other := filepath.Join(root, "Desktop", "holiday.txt")
	os.MkdirAll(filepath.Dir(bait), 0o755)
	os.WriteFile(bait, []byte("x"), 0o644)
	os.WriteFile(other, []byte("x"), 0o644)
	recent := filepath.Join(root, "Roaming", `Microsoft\Windows\Recent`)
	os.MkdirAll(recent, 0o755)
	baitLnk, otherLnk := filepath.Join(recent, "passwords.lnk"), filepath.Join(recent, "holiday.lnk")
	makeShortcut(t, baitLnk, bait)
	makeShortcut(t, otherLnk, other)

	b, _ := os.ReadFile(baitLnk)
	if got := LnkTarget(b); paths.Key(got) != paths.Key(bait) {
		t.Fatalf("LnkTarget = %q, want %q", got, bait)
	}
	removed := CleanRecent(filepath.Join(root, "Roaming"), map[string]string{strings.ToLower(bait): "desktop-passwords"})
	if len(removed) != 1 {
		t.Fatalf("removed %v", removed)
	}
	if _, err := os.Stat(baitLnk); !os.IsNotExist(err) {
		t.Error("shortcut to the bait was not removed")
	}
	if _, err := os.Stat(otherLnk); err != nil {
		t.Error("unrelated shortcut was removed")
	}
}

func TestLnkTargetIgnoresGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, []byte("not a shortcut"), make([]byte, 0x4C)} {
		if got := LnkTarget(b); got != "" {
			t.Errorf("LnkTarget(%q) = %q", b, got)
		}
	}
}

func TestMetamaskFollowsHostBrowser(t *testing.T) {
	u := testUser(t)
	// Brave + Vivaldi installed for real: MetaMask must go into the Yandex decoy.
	for _, p := range []string{`BraveSoftware\Brave-Browser\Application`, `Vivaldi\Application`} {
		os.MkdirAll(filepath.Join(u.LocalAppData, p), 0o755)
	}
	os.WriteFile(filepath.Join(u.LocalAppData, `BraveSoftware\Brave-Browser\Application\brave.exe`), nil, 0o644)
	os.WriteFile(filepath.Join(u.LocalAppData, `Vivaldi\Application\vivaldi.exe`), nil, 0o644)
	sel := map[string]bool{}
	for _, a := range Plan(u, nil) {
		if a.Available {
			sel[a.Spec.ID] = true
		}
	}
	if !sel["metamask"] || sel["brave"] || sel["vivaldi"] || !sel["yandex"] {
		t.Fatalf("unexpected availability: %v", sel)
	}
	u.DecoyBrowser = ChooseHost(sel)
	mm, _ := ByID("metamask")
	if got := mm.Files(u)[0].Path; !strings.Contains(got, `Yandex\YandexBrowser\User Data\Default\Local Extension Settings`) {
		t.Fatalf("metamask path = %s", got)
	}
}

// When a real app moves into a decoy's folder and saves its own data over our
// fake files, retiring the decoy must not delete that data.
func TestRemoveKeepsFilesTheRealAppRewrote(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Telegram Desktop")
	os.MkdirAll(filepath.Join(dir, "tdata"), 0o755)
	ours := filepath.Join(dir, "tdata", "D877F783D5D3EF8Cs")
	theirs := filepath.Join(dir, "tdata", "key_datas")
	stat := func(p string) config.BaitFile {
		fi, _ := os.Stat(p)
		return config.BaitFile{Path: p, Created: true, Size: fi.Size(), ModTime: fi.ModTime()}
	}
	os.WriteFile(ours, []byte("TDF$fake"), 0o644)
	os.WriteFile(theirs, []byte("TDF$fake"), 0o644)
	bs := &config.BaitState{Files: []config.BaitFile{stat(ours), stat(theirs)}, CreatedDirs: []string{dir}}

	// The real Telegram overwrites key_datas with the user's session.
	time.Sleep(20 * time.Millisecond)
	os.WriteFile(theirs, []byte("TDF$the user's real logged-in session"), 0o644)

	Remove(bs)
	if _, err := os.Stat(ours); !os.IsNotExist(err) {
		t.Error("untouched decoy file should be deleted")
	}
	if b, err := os.ReadFile(theirs); err != nil || !strings.Contains(string(b), "real") {
		t.Fatalf("real app data was deleted or damaged: %v", err)
	}
}

func TestRetireTakesDependentsWithIt(t *testing.T) {
	u := testUser(t)
	u.DecoyBrowser = "vivaldi"
	viv, _ := ByID("vivaldi")
	mm, _ := ByID("metamask")
	mk := func(s Spec) *config.BaitState {
		bs := &config.BaitState{ID: s.ID, Status: "ok"}
		for _, f := range s.Files(u) {
			os.MkdirAll(filepath.Dir(f.Path), 0o755)
			os.WriteFile(f.Path, []byte("x"), 0o644)
			fi, _ := os.Stat(f.Path)
			bs.Files = append(bs.Files, config.BaitFile{Path: f.Path, Created: true, Size: fi.Size(), ModTime: fi.ModTime()})
		}
		return bs
	}
	st := config.NewState()
	st.Baits["vivaldi"], st.Baits["metamask"] = mk(viv), mk(mm)
	st.Baits["desktop-passwords"] = &config.BaitState{ID: "desktop-passwords", Status: "ok",
		Files: []config.BaitFile{{Path: filepath.Join(u.Desktop, "passwords.txt")}}}

	got := Retire(st, u, "vivaldi", "real app installed")
	if len(got) != 2 || st.Baits["metamask"].Status != "retired" || st.Baits["desktop-passwords"].Status != "ok" {
		t.Fatalf("retired %v; metamask=%s desktop=%s", got, st.Baits["metamask"].Status, st.Baits["desktop-passwords"].Status)
	}
	if _, err := os.Stat(mm.Files(u)[0].Path); !os.IsNotExist(err) {
		t.Fatal("metamask decoy file left behind inside the real browser's folder")
	}
}

// A real app that moved into a decoy's folder keeps its files, including its
// own database LOCK file, when the decoy is removed.
func TestRemoveKeepsTheRealAppsLockFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "discord", "Local Storage", "leveldb")
	os.MkdirAll(dir, 0o755)
	ours := filepath.Join(dir, "000005.ldb")
	os.WriteFile(ours, []byte("fake"), 0o644)
	fi, _ := os.Stat(ours)
	bs := &config.BaitState{Files: []config.BaitFile{{Path: ours, Created: true, Size: fi.Size(), ModTime: fi.ModTime()}},
		CreatedDirs: []string{filepath.Dir(filepath.Dir(dir))}}
	theirLock := filepath.Join(dir, "LOCK") // created by the real Discord, not us
	os.WriteFile(theirLock, nil, 0o644)

	Remove(bs)
	if _, err := os.Stat(theirLock); err != nil {
		t.Fatal("deleted the real app's LOCK file")
	}
	if _, err := os.Stat(ours); !os.IsNotExist(err) {
		t.Fatal("our decoy file should be gone")
	}
}
