package trust

import (
	"strings"
	"testing"

	"github.com/xak1234/sentient1/internal/alerts"
	"github.com/xak1234/sentient1/internal/authenticode"
	"github.com/xak1234/sentient1/internal/classify"
)

func alert(image string, sig authenticode.Result, cmd string, baits ...string) *alerts.Alert {
	a := &alerts.Alert{ID: "a1", Process: &alerts.Process{Image: image, Signature: sig, CommandLine: cmd, SHA256: "ABCDEF0123456789"}}
	for _, b := range baits {
		a.Baits = append(a.Baits, alerts.BaitHit{ID: b})
	}
	return a
}

var signed = authenticode.Result{Signed: true, Valid: true, Signer: "Anomaly Innovations, Inc."}

func TestSignedAppTrustedForWhatItRead(t *testing.T) {
	a := alert(`C:\Users\bob\AppData\Local\Discord\app-1.0.9172\Discord.exe`, signed, "", "aws", "aws")
	r, why := Rule(a)
	if why != "" || r.Signer != signed.Signer || r.Path != `C:\Users\bob\AppData\Local\Discord\app-*\Discord.exe` ||
		len(r.Baits) != 1 || r.Baits[0] != "aws" || r.SHA256 != "" {
		t.Fatalf("rule=%+v why=%q", r, why)
	}
	if !OneClick(a) {
		t.Fatal("signed app: one click")
	}
}

func TestUnsignedPinnedToFile(t *testing.T) {
	a := alert(`C:\Users\bob\Downloads\mytool.exe`, authenticode.Result{}, "", "discord")
	r, why := Rule(a)
	if why != "" || r.SHA256 != "abcdef0123456789" || r.Path != a.Process.Image || r.Signer != "" {
		t.Fatalf("rule=%+v why=%q", r, why)
	}
	if OneClick(a) {
		t.Fatal("unsigned programs are never trusted from the frozen popup")
	}
}

func TestScriptHostPinnedToCommandLine(t *testing.T) {
	py := authenticode.Result{Signed: true, Valid: true, Signer: "Python Software Foundation"}
	a := alert(`C:\Python312\python.exe`, py, `python.exe C:\me\sync.py`, "aws")
	r, why := Rule(a)
	if why != "" || r.CommandLine != `python.exe C:\me\sync.py` || r.Signer == "" {
		t.Fatalf("rule=%+v why=%q", r, why)
	}
	if OneClick(a) {
		t.Fatal("script hosts are never trusted from the frozen popup")
	}
	a.Process.CommandLine = ""
	if _, why := Rule(a); !strings.Contains(why, "every script") {
		t.Fatalf("no command line: why=%q", why)
	}
}

func TestSweeps(t *testing.T) {
	a := alert(`C:\Program Files\Backblaze\bztransmit64.exe`, signed, "", "aws", "discord", "chrome")
	a.Verdict = classify.Verdict{Swept: []string{"aws", "chrome", "discord"}}
	r, why := Rule(a)
	if why != "" || len(r.Baits) != 0 {
		t.Fatalf("a program you say may read everything gets an all-bait rule: %+v %q", r, why)
	}
	w := alert(`C:\Windows\explorer.exe`, authenticode.Result{Signed: true, Valid: true, Signer: "Microsoft Windows"}, "", "aws", "discord", "chrome")
	w.Verdict = a.Verdict
	if _, why := Rule(w); why == "" {
		t.Fatal("a Windows program that swept baits must never be trusted permanently")
	}
}
