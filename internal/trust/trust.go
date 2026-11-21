// Package trust turns "it's mine" on an alert into an ignore rule that is as
// narrow as possible, so trusting your own app can't be reused by malware:
//
//   - it covers only the baits the app was seen reading (code injected into a
//     trusted app that goes after other baits still gets caught);
//   - a signed app is pinned to its folder and publisher;
//   - an unsigned one to that exact file (SHA-256), since anything can be
//     dropped at the same path later;
//   - a script host or runtime (python.exe, powershell.exe…) to the exact
//     command line: trusting one script must not trust every script.
//
// Some alerts can't be trusted permanently at all; "it's mine" then only
// undoes what SENTIENT1 did, this once.
package trust

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/xak1234/sentient1/internal/alerts"
	"github.com/xak1234/sentient1/internal/classify"
	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/procinfo"
)

// Rule returns the ignore rule for trusting the program in alert a. When the
// program can't be trusted permanently, why says so (and rule is empty).
func Rule(a *alerts.Alert) (rule config.IgnoreRule, why string) {
	p := a.Process
	if p == nil || p.Image == "" {
		return rule, "SENTIENT1 doesn't know which program it was"
	}
	exe := filepath.Base(p.Image)
	swept := len(a.Verdict.Swept) > 0
	windows := (&classify.Classifier{Env: classify.DefaultEnv()}).WindowsBinary(p.Image)

	rule.Note = "trusted " + time.Now().Format("2006-01-02") + " from alert " + a.ID
	if swept {
		// It went through several apps' data. Trusting that means trusting it
		// with every bait (a backup tool): only for an ordinary program.
		if windows || classify.ScriptHost(exe) {
			return config.IgnoreRule{}, exe + " went through several apps' data; that's never trusted for a Windows program or script host"
		}
	} else {
		for _, h := range a.Baits {
			if !containsFold(rule.Baits, h.ID) {
				rule.Baits = append(rule.Baits, h.ID)
			}
		}
	}

	switch {
	case classify.ScriptHost(exe):
		if strings.TrimSpace(p.CommandLine) == "" {
			return config.IgnoreRule{}, exe + " runs scripts and SENTIENT1 couldn't see which one, so trusting it would trust every script"
		}
		rule.Path, rule.CommandLine = p.Image, p.CommandLine
		if p.Signature.Valid {
			rule.Signer = p.Signature.Signer
		}
	case p.Signature.Valid:
		rule.Path, rule.Signer = classify.GeneralizePath(p.Image), p.Signature.Signer
	default:
		hash := p.SHA256
		if hash == "" {
			hash, _ = procinfo.FileSHA256(p.Image)
		}
		if hash == "" {
			return config.IgnoreRule{}, "SENTIENT1 couldn't fingerprint " + exe + " (it's unsigned, so it's only trusted by fingerprint)"
		}
		rule.Path, rule.SHA256 = p.Image, strings.ToLower(hash)
	}
	return rule, ""
}

// OneClick reports whether the frozen-alert popup may trust the program
// permanently with one click: only signed programs. Unsigned ones and script
// hosts are unfrozen just this once from the popup (`sentient1 trust` in a terminal
// still trusts them, pinned to the file or the command line).
func OneClick(a *alerts.Alert) bool {
	if _, why := Rule(a); why != "" {
		return false
	}
	return a.Process.Signature.Valid && !classify.ScriptHost(a.Process.Image)
}

// Describe explains in plain words what a rule covers.
func Describe(r config.IgnoreRule, names map[string]string) string {
	var parts []string
	switch {
	case r.CommandLine != "":
		parts = append(parts, "only this exact command: "+r.CommandLine)
	case r.SHA256 != "":
		parts = append(parts, "only this exact file (fingerprint "+short(r.SHA256)+"…)")
	case r.Signer != "":
		parts = append(parts, "signed by "+r.Signer)
	}
	if len(r.Baits) == 0 {
		parts = append(parts, "all baits")
	} else {
		var bs []string
		for _, b := range r.Baits {
			if n := names[b]; n != "" {
				b = n
			}
			bs = append(bs, b)
		}
		parts = append(parts, "only for: "+strings.Join(bs, ", "))
	}
	return strings.Join(parts, "; ")
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func containsFold(xs []string, x string) bool {
	for _, v := range xs {
		if strings.EqualFold(v, x) {
			return true
		}
	}
	return false
}
