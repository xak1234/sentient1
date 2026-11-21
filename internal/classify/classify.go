// Package classify decides how suspicious a bait reader is.
//
// The key insight: stealers almost always run as unsigned executables from
// user-writable folders (Temp, AppData, Downloads), or through script hosts and
// "living off the land" binaries. Malware without admin rights cannot write to
// Program Files or Windows, so location + signature is a strong, cheap signal.
package classify

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/xak1234/sentient1/internal/authenticode"
	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/paths"
)

// Bait is what the classifier needs to know about the touched bait.
type Bait struct {
	ID          string
	OwnerExes   []string // genuine app executables for a decoy (lowercase)
	OwnerSigner string   // substring of the genuine app's signer
	SharedSDK   bool     // read by a vendor SDK's default credential lookup (see baits.Spec)
}

type Verdict struct {
	Tier       config.Tier `json:"tier"`
	Ignored    bool        `json:"ignored,omitempty"`
	Reasons    []string    `json:"reasons"`
	DecoyOwner bool        `json:"decoyOwner,omitempty"` // the real app this decoy imitates is now installed
	Builtin    bool        `json:"builtin,omitempty"`    // Defender / Windows Search: never escalated
	ByRule     bool        `json:"byRule,omitempty"`     // ignored because of one of your rules
	Swept      []string    `json:"swept,omitempty"`      // bait IDs it went through (a sweep: several apps' data)
}

var lolbins = set(
	"powershell.exe", "powershell_ise.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
	"mshta.exe", "rundll32.exe", "regsvr32.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
	"regsvcs.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "tar.exe", "forfiles.exe",
	"cmstp.exe", "wmic.exe", "xcopy.exe", "robocopy.exe", "findstr.exe", "msxsl.exe", "hh.exe",
	"pcalua.exe", "scriptrunner.exe", "msdt.exe", "esentutl.exe", "expand.exe", "makecab.exe",
	// .NET Framework tools that stealers (RedLine, AgentTesla, Lumma…) hollow
	// out and run inside, so their reads look like a Microsoft-signed program.
	"applaunch.exe", "vbc.exe", "csc.exe", "jsc.exe", "aspnet_compiler.exe", "addinprocess.exe",
	"addinprocess32.exe", "addinutil.exe", "cvtres.exe", "caspol.exe", "ilasm.exe", "ieexec.exe",
)

// windowsReaders are the Windows programs with a real reason to open a file
// in your profile in the background (preview pane). Any other Windows program
// reading a bait is suspicious: malware hides inside them (injection).
var windowsReaders = set("prevhost.exe")

// ScriptHost reports whether name (an executable's file name) runs code it's
// given: what it does depends on the script, not on the program.
func ScriptHost(name string) bool {
	n := strings.ToLower(filepath.Base(name))
	return lolbins[n] || runtimes[n]
}

var runtimes = set(
	"python.exe", "pythonw.exe", "py.exe", "pyw.exe", "node.exe", "java.exe", "javaw.exe",
	"ruby.exe", "rubyw.exe", "perl.exe", "php.exe", "bun.exe", "deno.exe", "autoit3.exe",
	"autohotkey.exe", "autohotkey64.exe", "autohotkeyu64.exe", "dotnet.exe", "lua.exe", "tclsh.exe", "wish.exe",
)

// dropZones are where downloaded and double-clicked files land. AppData is left
// out on purpose: tools installed with npm or pip run their scripts from there.
var dropZones = []struct{ seg, name string }{
	{`\desktop\`, "Desktop"},
	{`\downloads\`, "Downloads folder"},
	{`\appdata\local\temp\`, "Temp folder"},
	{`\windows\temp\`, "Temp folder"},
}

// DroppedScript returns the first argument of a runtime's command line that is
// an absolute path in a drop zone (Desktop, Downloads, Temp), and which zone.
func DroppedScript(cmdline string) (path, where string) {
	args := SplitCommandLine(cmdline)
	for _, a := range args[min(1, len(args)):] {
		if len(a) < 3 || !(a[1] == ':' && (a[2] == '\\' || a[2] == '/') || strings.HasPrefix(a, `\\`)) {
			continue
		}
		p := strings.ToLower(strings.ReplaceAll(a, "/", `\`)) + `\`
		for _, z := range dropZones {
			if strings.Contains(p, z.seg) {
				return a, z.name
			}
		}
	}
	return "", ""
}

// SplitCommandLine splits a Windows command line into arguments (double quotes
// group, a backslash before a quote escapes it).
func SplitCommandLine(s string) []string {
	var args []string
	var cur strings.Builder
	inQuote, have := false, false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '\\' && i+1 < len(s) && s[i+1] == '"':
			cur.WriteByte('"')
			i++
			have = true
		case ch == '"':
			inQuote = !inQuote
			have = true
		case (ch == ' ' || ch == '\t') && !inQuote:
			if have {
				args = append(args, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteByte(ch)
			have = true
		}
	}
	if have {
		args = append(args, cur.String())
	}
	return args
}

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Built-in ignores: real-time AV and the search indexer touch everything.
// Matched on full path (dirs are admin-only), plus a Microsoft signature when known.
var builtinIgnore = []string{
	`%ProgramData%\Microsoft\Windows Defender\Platform\*\MsMpEng.exe`,
	`%ProgramData%\Microsoft\Windows Defender\Platform\*\MpDefenderCoreService.exe`,
	`%ProgramData%\Microsoft\Windows Defender\Platform\*\NisSrv.exe`,
	`%ProgramFiles%\Windows Defender\MsMpEng.exe`,
	`%SystemRoot%\System32\SearchProtocolHost.exe`,
	`%SystemRoot%\System32\SearchIndexer.exe`,
	`%SystemRoot%\System32\SearchFilterHost.exe`,
}

type location int

const (
	locKernel location = iota
	locSystem
	locProgramFiles
	locUserWritable
)

type Env struct {
	WinDir, WinTemp, ProgramFiles, ProgramFilesX86, ProgramData string
}

func DefaultEnv() Env {
	win := os.Getenv("SystemRoot")
	if win == "" {
		win = `C:\Windows`
	}
	pf := os.Getenv("ProgramW6432")
	if pf == "" {
		pf = os.Getenv("ProgramFiles")
	}
	return Env{
		WinDir:          win,
		WinTemp:         filepath.Join(win, "Temp"),
		ProgramFiles:    pf,
		ProgramFilesX86: os.Getenv("ProgramFiles(x86)"),
		ProgramData:     os.Getenv("ProgramData"),
	}
}

func (e Env) expand(p string) string {
	r := strings.NewReplacer("%ProgramData%", e.ProgramData, "%ProgramFiles%", e.ProgramFiles, "%SystemRoot%", e.WinDir)
	return r.Replace(p)
}

func (e Env) locate(image string, pid uint32) location {
	if pid == 4 || image == "" || strings.EqualFold(image, "System") {
		return locKernel
	}
	switch {
	case paths.Under(image, e.WinTemp):
		return locUserWritable
	case paths.Under(image, e.WinDir):
		return locSystem
	case paths.Under(image, e.ProgramFiles), e.ProgramFilesX86 != "" && paths.Under(image, e.ProgramFilesX86):
		return locProgramFiles
	case paths.Under(image, filepath.Join(e.ProgramData, `Microsoft\Windows Defender\Platform`)):
		return locProgramFiles
	}
	return locUserWritable
}

// Classifier holds the environment and user rules.
type Classifier struct {
	Env    Env
	Ignore []config.IgnoreRule
	// Optional probes (nil: unknown). Hash returns a file's SHA-256 (for rules
	// pinned to one file), CommandLine a process's command line (for rules
	// pinned to one script), UserSession whether it runs in a user's session.
	Hash        func(image string) string
	CommandLine func(pid uint32) string
	UserSession func(pid uint32) bool
}

// SweepExempt reports whether a reader may go through many apps' baits:
// Defender and Windows Search, or a program you trusted for all baits (e.g. a
// backup tool, with `sentient1 ignore add` or by trusting it from a sweep alert).
// Rules from trusting an app's single alert cover only that bait, so they
// don't exempt it. sig may be nil (not checked yet).
func (c *Classifier) SweepExempt(image string, pid uint32, sig *authenticode.Result) bool {
	signer := ""
	if sig != nil {
		signer = sig.Signer
	}
	for _, p := range builtinIgnore {
		if Glob(c.Env.expand(p), image) && (sig == nil || (sig.Valid && strings.Contains(signer, "Microsoft"))) {
			return true
		}
	}
	for _, r := range c.Ignore {
		if len(r.Baits) == 0 && c.ruleMatches(r, image, pid, "", signer, sig != nil) {
			return true
		}
	}
	return false
}

// WindowsBinary reports whether image lives in the Windows folder.
func (c *Classifier) WindowsBinary(image string) bool {
	return c.Env.locate(image, 1) == locSystem
}

// Prelim is the instant verdict before the (slower) signature check, assuming
// the binary is unsigned. Used to decide whether to freeze immediately.
func (c *Classifier) Prelim(image string, pid uint32, bait Bait) Verdict {
	return c.decide(image, pid, bait, nil)
}

// Final is the verdict once the signature is known.
func (c *Classifier) Final(image string, pid uint32, bait Bait, sig authenticode.Result) Verdict {
	return c.decide(image, pid, bait, &sig)
}

func (c *Classifier) decide(image string, pid uint32, bait Bait, sig *authenticode.Result) Verdict {
	name := strings.ToLower(filepath.Base(image))
	valid := sig != nil && sig.Valid
	signer := ""
	if sig != nil {
		signer = sig.Signer
	}

	for _, r := range c.Ignore {
		if c.ruleMatches(r, image, pid, bait.ID, signer, sig != nil) {
			why := "matches your ignore rule"
			if r.Note != "" {
				why += " (" + r.Note + ")"
			}
			return Verdict{Tier: config.TierInfo, Ignored: true, ByRule: true, Reasons: []string{why}}
		}
	}
	for _, p := range builtinIgnore {
		if Glob(c.Env.expand(p), image) && (sig == nil || (valid && strings.Contains(signer, "Microsoft"))) {
			return Verdict{Tier: config.TierInfo, Ignored: true, Builtin: true, Reasons: []string{"built-in: antivirus / search indexer"}}
		}
	}

	loc := c.Env.locate(image, pid)
	if loc == locKernel {
		return Verdict{Tier: config.TierWarn, Reasons: []string{"read by the kernel: usually a remote read over a network share (SMB)"}}
	}

	if sig != nil && valid && bait.OwnerSigner != "" && contains(bait.OwnerExes, name) &&
		strings.Contains(strings.ToLower(signer), strings.ToLower(bait.OwnerSigner)) {
		return Verdict{Tier: config.TierInfo, DecoyOwner: true,
			Reasons: []string{"the genuine " + signer + " app read its own (decoy) data: it looks like you installed it, so this decoy will be retired"}}
	}

	// Credential files every SDK reads on startup (~/.aws): a validly signed
	// app doing that is normal. Unsigned programs, script hosts and runtimes
	// still trip it, which is what stealers are.
	if sig != nil && valid && bait.SharedSDK && !lolbins[name] && !runtimes[name] {
		return Verdict{Tier: config.TierInfo, Ignored: true,
			Reasons: []string{"signed program (" + signer + ") doing the standard SDK credential lookup"}}
	}

	sigNote := "signature not checked yet"
	if sig != nil {
		sigNote = sig.String()
	}

	if lolbins[name] {
		return Verdict{Tier: config.TierCritical, Reasons: []string{name + " is a script host / built-in tool that malware commonly abuses", sigNote}}
	}
	if runtimes[name] {
		if valid {
			// The runtime is signed, but the program is the script it runs. One
			// sitting where downloads and double-clicked "games" land (a .jar on
			// the Desktop, a .py in Downloads) is what a stealer looks like.
			if c.CommandLine != nil {
				if script, where := DroppedScript(c.CommandLine(pid)); script != "" {
					return Verdict{Tier: config.TierCritical, Reasons: []string{
						name + " is running " + filepath.Base(script) + " from your " + where + ": typical of stealers disguised as games, cheats and tools", sigNote}}
				}
			}
			return Verdict{Tier: config.TierWarn, Reasons: []string{name + " is a scripting runtime: some script read the bait", sigNote}}
		}
		return Verdict{Tier: config.TierCritical, Reasons: []string{"unsigned scripting runtime " + name, sigNote}}
	}

	switch loc {
	case locSystem:
		if valid && (windowsReaders[name] || (c.UserSession != nil && !c.UserSession(pid))) {
			return Verdict{Tier: config.TierInfo, Reasons: []string{"Windows component", sigNote}}
		}
		if valid {
			return Verdict{Tier: config.TierWarn, Reasons: []string{name + " (part of Windows) has no reason to read app data: fine if you were copying or opening these files yourself, but malware also hides inside Windows programs", sigNote}}
		}
		return Verdict{Tier: config.TierWarn, Reasons: []string{"unsigned program inside the Windows folder", sigNote}}
	case locProgramFiles:
		if valid {
			return Verdict{Tier: config.TierInfo, Reasons: []string{"installed program (Program Files)", sigNote}}
		}
		return Verdict{Tier: config.TierWarn, Reasons: []string{"unsigned program in Program Files", sigNote}}
	default:
		if valid {
			return Verdict{Tier: config.TierWarn, Reasons: []string{"signed program running from a user-writable folder", sigNote}}
		}
		return Verdict{Tier: config.TierCritical, Reasons: []string{"unsigned program running from a user-writable folder (" + shortDir(image) + "): typical of stealers", sigNote}}
	}
}

func (c *Classifier) ruleMatches(r config.IgnoreRule, image string, pid uint32, baitID, signer string, sigKnown bool) bool {
	if r.Path == "" && r.Signer == "" && r.SHA256 == "" {
		return false
	}
	if !r.CoversBait(baitID) {
		return false
	}
	if r.Path != "" && !Glob(r.Path, image) {
		return false
	}
	if r.Signer != "" {
		if !sigKnown || !strings.Contains(strings.ToLower(signer), strings.ToLower(r.Signer)) {
			return false
		}
	}
	if r.SHA256 != "" {
		if c.Hash == nil || !strings.EqualFold(c.Hash(image), r.SHA256) {
			return false
		}
	}
	if r.CommandLine != "" {
		if c.CommandLine == nil || !SameCommandLine(c.CommandLine(pid), r.CommandLine) {
			return false
		}
	}
	return true
}

// SameCommandLine compares command lines, ignoring case and outer spaces.
func SameCommandLine(a, b string) bool {
	return a != "" && strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if strings.EqualFold(v, x) {
			return true
		}
	}
	return false
}

func shortDir(image string) string { return filepath.Dir(image) }

var (
	globMu    sync.Mutex
	globCache = map[string]*regexp.Regexp{}
)

// Glob matches a Windows path pattern case-insensitively: '*' within a path
// segment, '**' across segments, '?' one character.
func Glob(pattern, path string) bool {
	globMu.Lock()
	re, ok := globCache[pattern]
	globMu.Unlock()
	if !ok {
		var b strings.Builder
		b.WriteString("(?i)^")
		p := strings.ReplaceAll(pattern, "/", `\`)
		for i := 0; i < len(p); i++ {
			switch {
			case strings.HasPrefix(p[i:], "**"):
				b.WriteString(`.*`)
				i++
			case p[i] == '*':
				b.WriteString(`[^\\]*`)
			case p[i] == '?':
				b.WriteString(`[^\\]`)
			default:
				b.WriteString(regexp.QuoteMeta(string(p[i])))
			}
		}
		b.WriteString("$")
		re = regexp.MustCompile(b.String())
		globMu.Lock()
		globCache[pattern] = re
		globMu.Unlock()
	}
	return re.MatchString(strings.ReplaceAll(path, "/", `\`))
}

var versionRun = regexp.MustCompile(`\d+(?:[.\-_]\d+)+`)

// GeneralizePath turns version-specific paths into a stable ignore pattern, e.g.
// ...\Discord\app-1.0.9172\Discord.exe -> ...\Discord\app-*\Discord.exe
func GeneralizePath(image string) string {
	segs := strings.Split(image, `\`)
	for i := 0; i < len(segs)-1; i++ { // keep the file name exact
		segs[i] = versionRun.ReplaceAllString(segs[i], "*")
	}
	return strings.Join(segs, `\`)
}
