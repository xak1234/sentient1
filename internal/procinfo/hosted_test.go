package procinfo

import (
	"os"
	"strings"
	"testing"
)

func TestSurrogateIdentifier(t *testing.T) {
	const id = "{F544C724-92CF-41D5-85B7-65B02914E52D}"
	for _, test := range []struct{ command, want string }{
		{`"C:\Windows\System32\DllHost.exe" /Processid:` + id, id},
		{`dllhost.exe /PROCESSID:` + strings.ToLower(id), id},
		{`dllhost.exe /Processid:broken`, ""},
		{`dllhost.exe --text=` + id, ""},
		{`dllhost.exe /Processid:` + id + ` /Processid:{00000000-0000-0000-0000-000000000000}`, ""},
	} {
		if got := surrogateID(test.command); got != test.want {
			t.Errorf("%q: got %q, want %q", test.command, got, test.want)
		}
	}
}

func TestRundllModule(t *testing.T) {
	for _, test := range []struct{ command, want string }{
		{`rundll32.exe "C:\Program Files\Example\handler.dll",Start`, `C:\Program Files\Example\handler.dll`},
		{`rundll32.exe shell32.dll,Control_RunDLL`, "shell32.dll"},
		{`rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"`, ""},
		{`rundll32.exe`, ""},
	} {
		if got := rundllModule(test.command); got != test.want {
			t.Errorf("%q: got %q, want %q", test.command, got, test.want)
		}
	}
}

func TestModuleMatchDoesNotAttributeUnrelatedDLL(t *testing.T) {
	modules := []string{`C:\Program Files\One\handler.dll`, `C:\Windows\System32\kernel32.dll`}
	if got := matchModule(`handler.dll`, modules); got != modules[0] {
		t.Fatalf("unique registered filename: %q", got)
	}
	if got := matchModule(`C:\Other\handler.dll`, modules); got != "" {
		t.Fatalf("same basename at wrong absolute path attributed: %q", got)
	}
	if got := matchModule("unknown.dll", modules); got != "" {
		t.Fatalf("unrelated loaded DLL attributed: %q", got)
	}
	modules = append(modules, `C:\Program Files\Two\handler.dll`)
	if got := matchModule("handler.dll", modules); got != "" {
		t.Fatalf("ambiguous basename attributed: %q", got)
	}
}

func TestHostedUnknownHistoricalAndMultiple(t *testing.T) {
	unknown := ResolveHosted(0, `C:\Windows\System32\dllhost.exe`, "dllhost.exe", 0)
	if unknown == nil || unknown.Status != "unknown" || !unknown.Historical || len(unknown.Components) != 0 {
		t.Fatalf("unknown host: %+v", unknown)
	}
	if ResolveHosted(0, `C:\Apps\regular.exe`, "regular.exe", 0) != nil {
		t.Fatal("ordinary executable labelled a shared host")
	}
	multiple := HostedInfo{Status: "observed", Components: []HostedComponent{{Name: "A"}, {Name: "B"}}}
	if multiple.Label() != "2 hosted components" {
		t.Fatalf("ambiguous host attributed to one component: %s", multiple.Label())
	}
}

func TestRealProcessModuleSnapshotAndPIDGuard(t *testing.T) {
	pid := uint32(os.Getpid())
	modules, err := loadedModules(pid)
	if err != nil || len(modules) == 0 {
		t.Fatalf("real module snapshot: %v (%d modules)", err, len(modules))
	}
	created, err := CreateTime(pid)
	if err != nil {
		t.Fatal(err)
	}
	if Alive(pid, created+1) {
		t.Fatal("incorrect creation time accepted")
	}
	guarded := ResolveHosted(pid, `C:\Windows\System32\rundll32.exe`, "rundll32.exe kernel32.dll,Anything", created+1)
	if guarded.Status == "observed" || guarded.Components[0].Loaded || guarded.Components[0].Signature != nil {
		t.Fatalf("reused/unverified PID supplied module evidence: %+v", guarded)
	}
}
