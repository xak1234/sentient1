package classify

import (
	"testing"

	"github.com/xak1234/sentient1/internal/authenticode"
	"github.com/xak1234/sentient1/internal/config"
)

var env = Env{
	WinDir: `C:\Windows`, WinTemp: `C:\Windows\Temp`,
	ProgramFiles: `C:\Program Files`, ProgramFilesX86: `C:\Program Files (x86)`, ProgramData: `C:\ProgramData`,
}

var (
	ms       = authenticode.Result{Signed: true, Valid: true, Signer: "Microsoft Corporation"}
	discord  = authenticode.Result{Signed: true, Valid: true, Signer: "Discord Inc."}
	unsigned = authenticode.Result{}
	tampered = authenticode.Result{Signed: true, Valid: false, Error: "bad digest"}
)

func TestTiers(t *testing.T) {
	c := &Classifier{Env: env, UserSession: func(pid uint32) bool { return pid != 200 }}
	cases := []struct {
		name  string
		image string
		pid   uint32
		sig   authenticode.Result
		bait  Bait
		tier  config.Tier
		ign   bool
		owner bool
	}{
		{"stealer in temp", `C:\Users\bob\AppData\Local\Temp\x7f3\svchost.exe`, 100, unsigned, Bait{}, config.TierCritical, false, false},
		{"stealer in downloads", `C:\Users\bob\Downloads\FreeRobux.exe`, 100, unsigned, Bait{}, config.TierCritical, false, false},
		{"tampered sig in appdata", `C:\Users\bob\AppData\Roaming\upd.exe`, 100, tampered, Bait{}, config.TierCritical, false, false},
		{"copilot", `C:\Program Files (x86)\Microsoft\Copilot\Application\copilotapp.exe`, 100, ms, Bait{}, config.TierInfo, false, false},
		{"unsigned in program files", `C:\Program Files\Foo\foo.exe`, 100, unsigned, Bait{}, config.TierWarn, false, false},
		{"powershell", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, 100, ms, Bait{}, config.TierCritical, false, false},
		{"notepad (Windows program in your session)", `C:\Windows\System32\notepad.exe`, 100, ms, Bait{}, config.TierWarn, false, false},
		{"explorer", `C:\Windows\explorer.exe`, 100, ms, Bait{}, config.TierWarn, false, false},
		{"preview pane", `C:\Windows\System32\prevhost.exe`, 100, ms, Bait{}, config.TierInfo, false, false},
		{"Windows service (session 0)", `C:\Windows\System32\svchost.exe`, 200, ms, Bait{}, config.TierInfo, false, false},
		{"hollowing target AppLaunch", `C:\Windows\Microsoft.NET\Framework\v4.0.30319\AppLaunch.exe`, 100, ms, Bait{}, config.TierCritical, false, false},
		{"hollowing target vbc", `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\vbc.exe`, 100, ms, Bait{}, config.TierCritical, false, false},
		{"signed node in appdata", `C:\Users\bob\AppData\Roaming\nvm\v22\node.exe`, 100, authenticode.Result{Signed: true, Valid: true, Signer: "OpenJS Foundation"}, Bait{}, config.TierWarn, false, false},
		{"unsigned python", `C:\Users\bob\AppData\Local\Temp\_MEI1\python.exe`, 100, unsigned, Bait{}, config.TierCritical, false, false},
		{"signed app in user folder", `C:\Users\bob\AppData\Local\Programs\Microsoft VS Code\Code.exe`, 100, ms, Bait{}, config.TierWarn, false, false},
		{"smb/kernel", ``, 4, unsigned, Bait{}, config.TierWarn, false, false},
		{"defender", `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe`, 100, ms, Bait{}, config.TierInfo, true, false},
		{"fake defender in temp", `C:\Users\bob\AppData\Local\Temp\MsMpEng.exe`, 100, unsigned, Bait{}, config.TierCritical, false, false},
		{"windows temp", `C:\Windows\Temp\a.exe`, 100, unsigned, Bait{}, config.TierCritical, false, false},
		{"real discord owns decoy", `C:\Users\bob\AppData\Local\Discord\app-1.0.9172\Discord.exe`, 100, discord,
			Bait{ID: "discord", OwnerExes: []string{"discord.exe"}, OwnerSigner: "Discord"}, config.TierInfo, false, true},
		{"fake discord (unsigned) on decoy", `C:\Users\bob\AppData\Local\Discord\Discord.exe`, 100, unsigned,
			Bait{ID: "discord", OwnerExes: []string{"discord.exe"}, OwnerSigner: "Discord"}, config.TierCritical, false, false},
	}
	for _, tc := range cases {
		v := c.Final(tc.image, tc.pid, tc.bait, tc.sig)
		if v.Tier != tc.tier || v.Ignored != tc.ign || v.DecoyOwner != tc.owner {
			t.Errorf("%s: got %+v; want tier=%s ignored=%v owner=%v", tc.name, v, tc.tier, tc.ign, tc.owner)
		}
	}
}

func TestPrelimAssumesUnsigned(t *testing.T) {
	c := &Classifier{Env: env}
	if v := c.Prelim(`C:\Users\bob\AppData\Local\Programs\Microsoft VS Code\Code.exe`, 1, Bait{}); v.Tier != config.TierCritical {
		t.Fatalf("prelim for user-folder app should be critical (freeze first, verify after): %+v", v)
	}
	if v := c.Prelim(`C:\Program Files\Foo\foo.exe`, 1, Bait{}); v.Tier != config.TierWarn {
		t.Fatalf("prelim program files: %+v", v)
	}
}

func TestIgnoreRules(t *testing.T) {
	c := &Classifier{Env: env, Ignore: []config.IgnoreRule{
		{Path: `C:\Program Files (x86)\Microsoft\Copilot\**\copilotapp.exe`, Signer: "Microsoft"},
		{Path: `C:\Users\*\AppData\Local\Backblaze\bztransmit*.exe`},
	}}
	if v := c.Final(`C:\Program Files (x86)\Microsoft\Copilot\Application\copilotapp.exe`, 1, Bait{}, ms); !v.Ignored {
		t.Fatal("copilot rule should match")
	}
	// Same path but unsigned (e.g. replaced) must not match a signer rule.
	if v := c.Final(`C:\Program Files (x86)\Microsoft\Copilot\Application\copilotapp.exe`, 1, Bait{}, unsigned); v.Ignored {
		t.Fatal("signer rule matched an unsigned binary")
	}
	// Signer rules can't match before the signature is known.
	if v := c.Prelim(`C:\Program Files (x86)\Microsoft\Copilot\Application\copilotapp.exe`, 1, Bait{}); v.Ignored {
		t.Fatal("signer rule matched in prelim")
	}
	if v := c.Prelim(`C:\Users\bob\AppData\Local\Backblaze\bztransmit64.exe`, 1, Bait{}); !v.Ignored {
		t.Fatal("path-only rule should match in prelim")
	}
}

func TestGlobAndGeneralize(t *testing.T) {
	if !Glob(`C:\a\*\c.exe`, `c:\A\b\C.EXE`) || Glob(`C:\a\*\c.exe`, `C:\a\b\x\c.exe`) || !Glob(`C:\a\**\c.exe`, `C:\a\b\x\c.exe`) {
		t.Fatal("glob semantics")
	}
	got := GeneralizePath(`C:\Users\bob\AppData\Local\Discord\app-1.0.9172\Discord.exe`)
	if got != `C:\Users\bob\AppData\Local\Discord\app-*\Discord.exe` {
		t.Fatalf("generalize: %s", got)
	}
	got = GeneralizePath(`C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe`)
	if got != `C:\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe` {
		t.Fatalf("generalize: %s", got)
	}
}

func TestTrustRulesArePinned(t *testing.T) {
	hashes := map[string]string{`C:\Users\bob\Downloads\mytool.exe`: "aaaa"}
	cmd := map[uint32]string{1: `"C:\Python312\python.exe" C:\me\sync.py`, 2: `"C:\Python312\python.exe" C:\Temp\grab.py`}
	c := &Classifier{Env: env,
		Hash:        func(img string) string { return hashes[img] },
		CommandLine: func(pid uint32) string { return cmd[pid] },
		Ignore: []config.IgnoreRule{
			{Path: `C:\Users\*\AppData\Roaming\npm\**\opencode.exe`, Signer: "Anomaly", Baits: []string{"aws"}},
			{Path: `C:\Users\bob\Downloads\mytool.exe`, SHA256: "aaaa", Baits: []string{"discord"}},
			{Path: `C:\Python312\python.exe`, Signer: "Python Software Foundation", CommandLine: `"C:\Python312\python.exe" C:\me\sync.py`, Baits: []string{"aws"}},
		}}
	oc := `C:\Users\bob\AppData\Roaming\npm\node_modules\opencode-ai\bin\opencode.exe`
	anomaly := authenticode.Result{Signed: true, Valid: true, Signer: "Anomaly Innovations, Inc."}
	if v := c.Final(oc, 5, Bait{ID: "aws"}, anomaly); !v.Ignored || !v.ByRule {
		t.Fatalf("trusted app on its bait: %+v", v)
	}
	// The same trusted app going after another bait (injected code?) is not covered.
	if v := c.Final(oc, 5, Bait{ID: "discord"}, anomaly); v.Ignored {
		t.Fatalf("trust leaked to another bait: %+v", v)
	}
	// Unsigned trust is pinned to the file's hash: a different file at the same path isn't trusted.
	if v := c.Final(`C:\Users\bob\Downloads\mytool.exe`, 5, Bait{ID: "discord"}, unsigned); !v.Ignored {
		t.Fatalf("pinned unsigned tool: %+v", v)
	}
	hashes[`C:\Users\bob\Downloads\mytool.exe`] = "bbbb"
	if v := c.Final(`C:\Users\bob\Downloads\mytool.exe`, 5, Bait{ID: "discord"}, unsigned); v.Ignored {
		t.Fatalf("replaced file still trusted: %+v", v)
	}
	// Runtimes are pinned to one command line.
	psf := authenticode.Result{Signed: true, Valid: true, Signer: "Python Software Foundation"}
	if v := c.Final(`C:\Python312\python.exe`, 1, Bait{ID: "aws"}, psf); !v.Ignored {
		t.Fatalf("trusted script: %+v", v)
	}
	if v := c.Final(`C:\Python312\python.exe`, 2, Bait{ID: "aws"}, psf); v.Ignored {
		t.Fatalf("another script trusted through python.exe: %+v", v)
	}
}

func TestRuntimeRunningADroppedScript(t *testing.T) {
	java := `C:\Program Files\Eclipse Adoptium\jre-21.0.13.9-hotspot\bin\javaw.exe`
	cmd := map[uint32]string{
		1:  `"` + java + `" -jar "C:\Users\bob\Desktop\zombiesurvival.jar"`,
		2:  `"C:\Python312\pythonw.exe" C:\Users\bob\Downloads\free_nitro.pyw`,
		3:  `node "C:\Users\bob\AppData\Local\Temp\x1\run.js" --silent`,
		5:  `"` + java + `" -jar C:\Users\bob\OneDrive\Desktop\mod.jar`, // pid 4 is the kernel
		10: `"C:\Python312\python.exe" C:\Users\bob\code\sync.py`,
		11: `node C:\Users\bob\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js`,
		12: `"C:\Python312\python.exe" -c "print(1)"`,
		13: `"C:\Python312\python.exe" sync.py --out C:\Users\bob\Downloads`,
	}
	c := &Classifier{Env: env, CommandLine: func(pid uint32) string { return cmd[pid] }}
	signed := authenticode.Result{Signed: true, Valid: true, Signer: "Eclipse.org Foundation, Inc."}
	for pid, img := range map[uint32]string{1: java, 2: `C:\Python312\pythonw.exe`, 3: `C:\Program Files\nodejs\node.exe`, 5: java} {
		if v := c.Final(img, pid, Bait{ID: "discord"}, signed); v.Tier != config.TierCritical {
			t.Errorf("pid %d (%s): a script from a drop zone must be critical, got %+v", pid, cmd[pid], v)
		}
	}
	// Scripts kept elsewhere (your projects, npm/pip tools in AppData) stay a warning.
	for pid, img := range map[uint32]string{10: `C:\Python312\python.exe`, 11: `C:\Program Files\nodejs\node.exe`, 12: `C:\Python312\python.exe`} {
		if v := c.Final(img, pid, Bait{ID: "discord"}, signed); v.Tier != config.TierWarn {
			t.Errorf("pid %d (%s): want warn, got %+v", pid, cmd[pid], v)
		}
	}
	if v := c.Final(`C:\Python312\python.exe`, 13, Bait{ID: "discord"}, signed); v.Tier != config.TierCritical {
		// A drop-zone path anywhere on the command line counts: we can't tell a
		// script from an argument, and reading a bait is enough to be wrong here.
		t.Errorf("drop-zone argument: %+v", v)
	}
	if got, where := DroppedScript(cmd[1]); got != `C:\Users\bob\Desktop\zombiesurvival.jar` || where != "Desktop" {
		t.Fatalf("DroppedScript: %q %q", got, where)
	}
}

func TestSplitCommandLine(t *testing.T) {
	got := SplitCommandLine(`"C:\Program Files\x\a.exe" -jar "C:\a b\c.jar"  plain "q\"uote"`)
	want := []string{`C:\Program Files\x\a.exe`, "-jar", `C:\a b\c.jar`, "plain", `q"uote`}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("arg %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestSweepExempt(t *testing.T) {
	c := &Classifier{Env: env, Ignore: []config.IgnoreRule{
		{Path: `C:\Program Files\Backblaze\bztransmit64.exe`, Signer: "Backblaze"},
		{Path: `C:\Program Files\Foo\foo.exe`, Signer: "Foo", Baits: []string{"aws"}},
	}}
	bb := authenticode.Result{Signed: true, Valid: true, Signer: "Backblaze, Inc."}
	if !c.SweepExempt(`C:\Program Files\Backblaze\bztransmit64.exe`, 1, &bb) {
		t.Fatal("all-bait rule should allow sweeps")
	}
	foo := authenticode.Result{Signed: true, Valid: true, Signer: "Foo Ltd"}
	if c.SweepExempt(`C:\Program Files\Foo\foo.exe`, 1, &foo) {
		t.Fatal("single-bait trust must not allow sweeps")
	}
	if !c.SweepExempt(`C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1-0\MsMpEng.exe`, 1, &ms) {
		t.Fatal("defender")
	}
	if c.SweepExempt(`C:\Windows\explorer.exe`, 1, &ms) {
		t.Fatal("explorer must not be sweep-exempt")
	}
}
