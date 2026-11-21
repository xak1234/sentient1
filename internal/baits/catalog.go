// Package baits defines every bait SENTIENT1 can plant (plain files and fake
// application data that stealers target), decides which ones fit this PC, and
// creates, checks, retires and removes them.
package baits

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xak1234/sentient1/internal/config"
)

// Kind of bait.
const (
	KindFile   = "file"   // a tempting document in your folders
	KindDecoy  = "decoy"  // fake data for an app you don't use
	KindCanary = "canary" // credentials that phone home when used
)

// Spec describes one bait in the catalog.
type Spec struct {
	ID          string
	Name        string
	Category    string
	Kind        string
	Description string
	Default     bool   // preselected when available
	Caveat      string // shown for opt-in baits
	// Root is the app's data folder. If it already exists before install, the
	// real app is (or was) installed and this decoy is unavailable.
	Root func(u config.UserInfo) string
	// Markers are globs whose existence means the genuine app is installed.
	Markers   func(u config.UserInfo) []string
	OwnerExes []string // genuine executables (lowercase)
	Signer    string   // substring of the genuine app's signer
	// SharedSDK: the file sits where a vendor SDK's default credential lookup
	// reads on startup, so many legitimate signed apps touch it. Signed,
	// non-script readers are logged but not alerted; everything else trips it.
	SharedSDK bool
	// RequiresAny: this bait lives inside one of these (e.g. MetaMask inside a fake browser).
	RequiresAny []string
	Files       func(u config.UserInfo) []FileSpec
}

// FileSpec is one file of a bait.
type FileSpec struct {
	Path  string
	Audit bool // put the read/delete audit rule on it
	Text  bool // human-readable (shown by `bait show`)
	Gen   func(g *Gen) []byte
}

func pf() string   { return env("ProgramW6432", env("ProgramFiles", `C:\Program Files`)) }
func pf86() string { return env("ProgramFiles(x86)", `C:\Program Files (x86)`) }

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func j(parts ...string) string { return filepath.Join(parts...) }

const metamaskID = "nkbihfbeogaeaoehlefnkodbefgpgknn"

// decoyBrowsers can host fake extension data, in order of preference.
var decoyBrowsers = []string{"vivaldi", "yandex", "brave"}

// BrowserUserData returns a decoy browser's "User Data" folder.
func BrowserUserData(u config.UserInfo, id string) string {
	switch id {
	case "yandex":
		return j(u.LocalAppData, `Yandex\YandexBrowser\User Data`)
	case "brave":
		return j(u.LocalAppData, `BraveSoftware\Brave-Browser\User Data`)
	}
	return j(u.LocalAppData, `Vivaldi\User Data`)
}

// ChooseHost picks the decoy browser that will host dependent baits (MetaMask)
// from the selected IDs. Returns "" if none is selected.
func ChooseHost(selected map[string]bool) string {
	for _, b := range decoyBrowsers {
		if selected[b] {
			return b
		}
	}
	return ""
}

func chromiumFiles(userData string, passwords string) []FileSpec {
	if passwords == "" {
		passwords = "Login Data"
	}
	return []FileSpec{
		{Path: j(userData, "Local State"), Audit: true, Gen: genLocalState},
		{Path: j(userData, "Default", passwords), Audit: true, Gen: genEmptySQLite},
		{Path: j(userData, "Default", "Network", "Cookies"), Audit: true, Gen: genEmptySQLite},
		{Path: j(userData, "Default", "Web Data"), Audit: true, Gen: genEmptySQLite},
		{Path: j(userData, "Default", "Preferences"), Gen: genPreferences},
	}
}

// Catalog lists every bait, in display order.
var Catalog = []Spec{
	// ---- Files ----
	{
		ID: "home-passwords", Name: "passwords.txt in your home folder", Category: "Files", Kind: KindFile, Default: true,
		Description: "Scripts and dev-tool based stealers sweep the home folder.",
		Files: func(u config.UserInfo) []FileSpec {
			return []FileSpec{{Path: j(u.Profile, "passwords.txt"), Audit: true, Text: true, Gen: genPasswordsTxt}}
		},
	},
	{
		ID: "documents-passwords", Name: "passwords.txt in Documents", Category: "Files", Kind: KindFile, Default: true,
		Description: "File grabbers sweep Documents for *.txt with names like password/wallet/seed.",
		Files: func(u config.UserInfo) []FileSpec {
			return []FileSpec{{Path: j(u.Documents, "passwords.txt"), Audit: true, Text: true, Gen: genPasswordsTxt}}
		},
	},
	{
		ID: "desktop-passwords", Name: "passwords.txt on the Desktop", Category: "Files", Kind: KindFile, Default: true,
		Description: "The #1 folder file grabbers look in. You'll see it every day: don't open it.",
		Files: func(u config.UserInfo) []FileSpec {
			return []FileSpec{{Path: j(u.Desktop, "passwords.txt"), Audit: true, Text: true, Gen: genPasswordsTxt}}
		},
	},
	{
		ID: "seed-phrase", Name: "wallet recovery phrase (Documents)", Category: "Files", Kind: KindFile, Default: true,
		Description: "Crypto stealers grep for 'seed', 'wallet', 'recovery'.",
		Files: func(u config.UserInfo) []FileSpec {
			return []FileSpec{{Path: j(u.Documents, "wallet recovery phrase.txt"), Audit: true, Text: true, Gen: genSeedTxt}}
		},
	},
	{
		ID: "backup-codes", Name: "2FA backup codes (Documents)", Category: "Files", Kind: KindFile, Default: true,
		Description: "Backup codes bypass 2FA, so stealers grab them.",
		Files: func(u config.UserInfo) []FileSpec {
			return []FileSpec{{Path: j(u.Documents, "google backup codes.txt"), Audit: true, Text: true, Gen: genBackupCodes}}
		},
	},
	{
		ID: "keepass", Name: "KeePass database (Documents)", Category: "Files", Kind: KindFile, Default: true,
		Description: "Stealers collect *.kdbx files to crack offline.",
		Files: func(u config.UserInfo) []FileSpec {
			return []FileSpec{{Path: j(u.Documents, "Passwords.kdbx"), Audit: true, Gen: genKdbx}}
		},
	},

	// ---- Browsers you don't use ----
	{
		ID: "brave", Name: "Brave browser profile", Category: "Browsers", Kind: KindDecoy, Default: true,
		Description: "Fake saved passwords + cookies. Nothing legit reads them if you don't use Brave.",
		Root:        func(u config.UserInfo) string { return j(u.LocalAppData, `BraveSoftware\Brave-Browser`) },
		Markers: func(u config.UserInfo) []string {
			return []string{j(u.LocalAppData, `BraveSoftware\Brave-Browser\Application\brave.exe`), j(pf(), `BraveSoftware\Brave-Browser\Application\brave.exe`), j(pf86(), `BraveSoftware\Brave-Browser\Application\brave.exe`)}
		},
		OwnerExes: []string{"brave.exe"}, Signer: "Brave Software",
		Files: func(u config.UserInfo) []FileSpec {
			return chromiumFiles(j(u.LocalAppData, `BraveSoftware\Brave-Browser\User Data`), "")
		},
	},
	{
		ID: "opera", Name: "Opera browser profile", Category: "Browsers", Kind: KindDecoy, Default: true,
		Description: "Fake saved passwords + cookies.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, `Opera Software`) },
		Markers: func(u config.UserInfo) []string {
			return []string{j(u.LocalAppData, `Programs\Opera\opera.exe`), j(u.LocalAppData, `Programs\Opera\launcher.exe`), j(u.LocalAppData, `Programs\Opera GX\opera.exe`), j(pf(), `Opera\opera.exe`)}
		},
		OwnerExes: []string{"opera.exe", "launcher.exe"}, Signer: "Opera Norway",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.RoamingAppData, `Opera Software\Opera Stable`)
			return []FileSpec{
				{Path: j(d, "Local State"), Audit: true, Gen: genLocalState},
				{Path: j(d, "Default", "Login Data"), Audit: true, Gen: genEmptySQLite},
				{Path: j(d, "Default", "Network", "Cookies"), Audit: true, Gen: genEmptySQLite},
			}
		},
	},
	{
		ID: "vivaldi", Name: "Vivaldi browser profile", Category: "Browsers", Kind: KindDecoy, Default: true,
		Description: "Fake saved passwords + cookies.",
		Root:        func(u config.UserInfo) string { return j(u.LocalAppData, `Vivaldi`) },
		Markers: func(u config.UserInfo) []string {
			return []string{j(u.LocalAppData, `Vivaldi\Application\vivaldi.exe`), j(pf(), `Vivaldi\Application\vivaldi.exe`)}
		},
		OwnerExes: []string{"vivaldi.exe"}, Signer: "Vivaldi Technologies",
		Files: func(u config.UserInfo) []FileSpec { return chromiumFiles(j(u.LocalAppData, `Vivaldi\User Data`), "") },
	},
	{
		ID: "yandex", Name: "Yandex browser profile", Category: "Browsers", Kind: KindDecoy, Default: true,
		Description: "Yandex's password store is on every stealer's list.",
		Root:        func(u config.UserInfo) string { return j(u.LocalAppData, `Yandex`) },
		Markers: func(u config.UserInfo) []string {
			return []string{j(u.LocalAppData, `Yandex\YandexBrowser\Application\browser.exe`)}
		},
		OwnerExes: []string{"browser.exe"}, Signer: "YANDEX",
		Files: func(u config.UserInfo) []FileSpec {
			return chromiumFiles(j(u.LocalAppData, `Yandex\YandexBrowser\User Data`), "Ya Passman Data")
		},
	},
	{
		ID: "firefox", Name: "Firefox profile", Category: "Browsers", Kind: KindDecoy,
		Description: "Fake logins.json + key4.db.",
		Caveat:      "If you install Firefox later it may pick up this fake profile before SENTIENT1 retires it.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, `Mozilla\Firefox`) },
		Markers: func(u config.UserInfo) []string {
			return []string{j(pf(), `Mozilla Firefox\firefox.exe`), j(pf86(), `Mozilla Firefox\firefox.exe`)}
		},
		OwnerExes: []string{"firefox.exe"}, Signer: "Mozilla",
		Files: func(u config.UserInfo) []FileSpec {
			base := j(u.RoamingAppData, `Mozilla\Firefox`)
			prof := j(base, "Profiles", "q8m3kx2v.default-release")
			return []FileSpec{
				{Path: j(base, "profiles.ini"), Gen: genProfilesIni},
				{Path: j(prof, "logins.json"), Audit: true, Gen: genFirefoxLogins},
				{Path: j(prof, "key4.db"), Audit: true, Gen: genEmptySQLite},
				{Path: j(prof, "cookies.sqlite"), Audit: true, Gen: genEmptySQLite},
			}
		},
	},

	// ---- Wallets ----
	{
		ID: "metamask", Name: "MetaMask wallet (inside a fake browser)", Category: "Wallets", Kind: KindDecoy, Default: true,
		RequiresAny: decoyBrowsers,
		Description: "The most targeted wallet extension. Lives inside one of the fake browser profiles.",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(BrowserUserData(u, u.DecoyBrowser), "Default", "Local Extension Settings", metamaskID)
			return []FileSpec{
				{Path: j(d, "000003.log"), Audit: true, Gen: genMetamaskLog},
				{Path: j(d, "CURRENT"), Audit: true, Gen: func(*Gen) []byte { return []byte("MANIFEST-000001\n") }},
				{Path: j(d, "LOCK"), Gen: func(*Gen) []byte { return nil }},
				{Path: j(d, "MANIFEST-000001"), Gen: genLevelDBManifest},
			}
		},
	},
	{
		ID: "exodus", Name: "Exodus wallet", Category: "Wallets", Kind: KindDecoy, Default: true,
		Description: "Fake seed.seco + passphrase.json.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, `Exodus`) },
		Markers:     func(u config.UserInfo) []string { return []string{j(u.LocalAppData, `exodus\Exodus.exe`)} },
		OwnerExes:   []string{"exodus.exe"}, Signer: "Exodus Movement",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.RoamingAppData, `Exodus\exodus.wallet`)
			return []FileSpec{
				{Path: j(d, "seed.seco"), Audit: true, Gen: genSeco},
				{Path: j(d, "passphrase.json"), Audit: true, Gen: genExodusPassphrase},
				{Path: j(d, "info.seco"), Audit: true, Gen: genSeco},
			}
		},
	},
	{
		ID: "electrum", Name: "Electrum wallet", Category: "Wallets", Kind: KindDecoy, Default: true,
		Description: "Fake default_wallet file.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, `Electrum`) },
		Markers: func(u config.UserInfo) []string {
			return []string{j(pf86(), `Electrum\*.exe`), j(pf(), `Electrum\*.exe`)}
		},
		Files: func(u config.UserInfo) []FileSpec {
			return []FileSpec{{Path: j(u.RoamingAppData, `Electrum\wallets\default_wallet`), Audit: true, Gen: genElectrumWallet}}
		},
	},
	{
		ID: "atomic", Name: "Atomic Wallet", Category: "Wallets", Kind: KindDecoy, Default: true,
		Description: "Fake wallet storage.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, `atomic`) },
		Markers: func(u config.UserInfo) []string {
			return []string{j(u.LocalAppData, `Programs\atomic\Atomic Wallet.exe`)}
		},
		OwnerExes: []string{"atomic wallet.exe"}, Signer: "Atomic",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.RoamingAppData, `atomic\Local Storage\leveldb`)
			return []FileSpec{
				{Path: j(d, "000003.log"), Audit: true, Gen: genAtomicLog},
				{Path: j(d, "CURRENT"), Audit: true, Gen: func(*Gen) []byte { return []byte("MANIFEST-000001\n") }},
			}
		},
	},

	// ---- Messaging & gaming ----
	{
		ID: "telegram", Name: "Telegram Desktop session", Category: "Apps", Kind: KindDecoy, Default: true,
		Description: "Stolen tdata = logged-in Telegram account.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, `Telegram Desktop`) },
		Markers: func(u config.UserInfo) []string {
			return []string{j(u.RoamingAppData, `Telegram Desktop\Telegram.exe`), j(u.LocalAppData, `Packages\TelegramMessengerLLP.TelegramDesktop_*`)}
		},
		OwnerExes: []string{"telegram.exe"}, Signer: "Telegram",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.RoamingAppData, `Telegram Desktop\tdata`)
			return []FileSpec{
				{Path: j(d, "key_datas"), Audit: true, Gen: genTDF},
				{Path: j(d, "D877F783D5D3EF8C", "maps"), Audit: true, Gen: genTDF},
				{Path: j(d, "D877F783D5D3EF8Cs"), Audit: true, Gen: genTDF},
			}
		},
	},
	{
		ID: "discord", Name: "Discord token store", Category: "Apps", Kind: KindDecoy, Default: true,
		Description: "Token grabbers read Discord's Local Storage.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, `discord`) },
		Markers: func(u config.UserInfo) []string {
			return []string{j(u.LocalAppData, `Discord\Update.exe`), j(u.LocalAppData, `DiscordPTB\Update.exe`), j(u.LocalAppData, `DiscordCanary\Update.exe`)}
		},
		OwnerExes: []string{"discord.exe", "update.exe"}, Signer: "Discord",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.RoamingAppData, `discord\Local Storage\leveldb`)
			return []FileSpec{
				{Path: j(d, "000005.ldb"), Audit: true, Gen: genDiscordLdb},
				{Path: j(d, "CURRENT"), Audit: true, Gen: func(*Gen) []byte { return []byte("MANIFEST-000001\n") }},
				{Path: j(d, "LOCK"), Gen: func(*Gen) []byte { return nil }},
			}
		},
	},
	{
		ID: "filezilla", Name: "FileZilla saved servers", Category: "Apps", Kind: KindDecoy, Default: true,
		Description: "Saved FTP/SFTP logins.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, `FileZilla`) },
		Markers: func(u config.UserInfo) []string {
			return []string{j(pf(), `FileZilla FTP Client\filezilla.exe`), j(pf86(), `FileZilla FTP Client\filezilla.exe`)}
		},
		OwnerExes: []string{"filezilla.exe"}, Signer: "Tim Kosse",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.RoamingAppData, "FileZilla")
			return []FileSpec{
				{Path: j(d, "sitemanager.xml"), Audit: true, Text: true, Gen: genSiteManager},
				{Path: j(d, "recentservers.xml"), Audit: true, Text: true, Gen: genRecentServers},
			}
		},
	},

	// ---- Cloud & dev credentials ----
	{
		ID: "aws", Name: "AWS credentials (~/.aws)", Category: "Credentials", Kind: KindCanary, Default: true,
		Description: "With canary tokens on, these keys email you if anyone ever uses them.",
		Root:        func(u config.UserInfo) string { return j(u.Profile, ".aws") },
		Markers:     func(u config.UserInfo) []string { return []string{j(pf(), `Amazon\AWSCLIV2\aws.exe`)} },
		OwnerExes:   []string{"aws.exe"}, Signer: "Amazon",
		// Every AWS SDK looks here on startup (OpenCode, Claude Code, VS Code, Terraform…).
		SharedSDK: true,
		Files: func(u config.UserInfo) []FileSpec {
			return []FileSpec{
				{Path: j(u.Profile, ".aws", "credentials"), Audit: true, Text: true, Gen: genAWSCredentials},
				{Path: j(u.Profile, ".aws", "config"), Text: true, Gen: genAWSConfig},
			}
		},
	},
	{
		ID: "ssh-backup", Name: "Old SSH key backup (~/.ssh)", Category: "Credentials", Kind: KindFile,
		Description: "Grabbers copy the whole .ssh folder.",
		Caveat:      "Goes in your real .ssh folder. ssh never reads this file name, but tools that scan .ssh will trip it.",
		Files: func(u config.UserInfo) []FileSpec {
			return []FileSpec{{Path: j(u.Profile, ".ssh", "id_rsa_backup_2023"), Audit: true, Gen: genSSHKey}}
		},
	},
}

// ByID finds a spec.
func ByID(id string) (Spec, bool) {
	for _, s := range Catalog {
		if s.ID == id {
			return s, true
		}
	}
	return Spec{}, false
}

// Availability of a bait on this PC.
type Availability struct {
	Spec      Spec
	Available bool
	Reason    string // why not
}

// Plan reports which catalog baits fit this user. alreadyOurs lists bait IDs
// SENTIENT1 already created (their Root existing is expected, not a real app).
func Plan(u config.UserInfo, alreadyOurs map[string]bool) []Availability {
	var out []Availability
	avail := map[string]bool{}
	for _, s := range Catalog {
		a := Availability{Spec: s, Available: true}
		if s.Markers != nil {
			if m := firstExisting(s.Markers(u)); m != "" {
				a.Available, a.Reason = false, "you have it installed ("+m+")"
			}
		}
		if a.Available && s.Root != nil && !alreadyOurs[s.ID] {
			if _, err := os.Stat(s.Root(u)); err == nil {
				a.Available, a.Reason = false, "its data folder already exists (you use or used it)"
			}
		}
		if a.Available && s.Kind == KindFile && !alreadyOurs[s.ID] {
			for _, f := range s.Files(u) {
				if _, err := os.Stat(filepath.Dir(f.Path)); err != nil {
					a.Available, a.Reason = false, "folder "+filepath.Dir(f.Path)+" doesn't exist"
				}
			}
		}
		if a.Available && len(s.RequiresAny) > 0 {
			ok := false
			for _, r := range s.RequiresAny {
				ok = ok || avail[r]
			}
			if !ok {
				a.Available, a.Reason = false, "needs one of the fake browsers ("+strings.Join(s.RequiresAny, ", ")+"), and you use all of them"
			}
		}
		avail[s.ID] = a.Available
		out = append(out, a)
	}
	return out
}

// InstalledMarker returns the first marker that exists (the real app is now installed).
func InstalledMarker(s Spec, u config.UserInfo) string {
	if s.Markers == nil {
		return ""
	}
	return firstExisting(s.Markers(u))
}

func firstExisting(globs []string) string {
	for _, g := range globs {
		if strings.ContainsAny(g, "*?[") {
			if m, _ := filepath.Glob(g); len(m) > 0 {
				return m[0]
			}
			continue
		}
		if _, err := os.Stat(g); err == nil {
			return g
		}
	}
	return ""
}

// Categories returns category names in catalog order.
func Categories() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range Catalog {
		if !seen[s.Category] {
			seen[s.Category] = true
			out = append(out, s.Category)
		}
	}
	return out
}

// DependentsOf returns IDs that require id.
func DependentsOf(id string) []string {
	var out []string
	for _, s := range Catalog {
		for _, r := range s.RequiresAny {
			if r == id {
				out = append(out, s.ID)
			}
		}
	}
	sort.Strings(out)
	return out
}

// CustomSpec builds a spec for a user-chosen file (adopted if it exists,
// otherwise filled with a fake passwords list).
func CustomSpec(id, path string) Spec {
	return Spec{
		ID: id, Name: filepath.Base(path) + " (custom)", Category: "Custom", Kind: KindFile,
		Files: func(config.UserInfo) []FileSpec {
			return []FileSpec{{Path: path, Audit: true, Text: true, Gen: genPasswordsTxt}}
		},
	}
}

// SpecFor resolves a configured bait (catalog or custom).
func SpecFor(b config.BaitConfig) (Spec, bool) {
	if b.Path != "" {
		return CustomSpec(b.ID, b.Path), true
	}
	return ByID(b.ID)
}

// SpecByID resolves an ID using the config's custom baits too.
func SpecByID(cfg *config.Config, id string) (Spec, bool) {
	for _, b := range cfg.Baits {
		if b.ID == id {
			return SpecFor(b)
		}
	}
	return ByID(id)
}
