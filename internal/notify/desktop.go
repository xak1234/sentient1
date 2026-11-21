package notify

import (
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unicode/utf16"

	"golang.org/x/sys/windows"

	"github.com/xak1234/sentient1/internal/alerts"
	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/trust"
)

// Toast shows a Windows notification (best effort, non-blocking).
func Toast(title, body string) {
	esc := func(s string) string {
		r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
		return r.Replace(s)
	}
	xml := fmt.Sprintf(`<toast><visual><binding template="ToastGeneric"><text>%s</text><text>%s</text></binding></visual><audio src="ms-winsoundevent:Notification.Looping.Alarm2"/></toast>`, esc(title), esc(body))
	script := `
[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
$x = New-Object Windows.Data.Xml.Dom.XmlDocument
$x.LoadXml(@'
` + xml + `
'@)
$id = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($id).Show([Windows.UI.Notifications.ToastNotification]::new($x))
`
	u := utf16.Encode([]rune(script))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", base64.StdEncoding.EncodeToString(b))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	// PowerShell may print progress records; only a failed run is an error.
	if out, err := toastRun(cmd); err != nil {
		lastToastErr = fmt.Sprintf("%v %s", err, out)
	}
}

const (
	mbOK            = 0x0
	mbYesNoCancel   = 0x3
	mbYesNo         = 0x4
	mbIconError     = 0x10
	mbIconWarning   = 0x30
	mbIconInfo      = 0x40
	mbSetForeground = 0x10000
	mbTopmost       = 0x40000
	idYes           = 6
	idNo            = 7
)

func messageBox(title, text string, flags uint32) int32 {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString(title)
	r, _ := windows.MessageBox(0, t, c, flags|mbTopmost|mbSetForeground)
	return r
}

// RunElevated starts sentient1 with args via a UAC prompt (the click is the proof
// a human, not malware, asked for it).
func RunElevated(exe string, args ...string) error {
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	a, _ := windows.UTF16PtrFromString(strings.Join(quoteAll(args), " "))
	return windows.ShellExecute(0, verb, file, a, nil, windows.SW_SHOWNORMAL)
}

func quoteAll(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = syscall.EscapeArg(a)
	}
	return out
}

// Details renders the long form of an alert for the popup.
func Details(a *alerts.Alert) string {
	// Message boxes use a proportional font, so no column alignment: one
	// labelled line per fact, long paths on their own line.
	var b strings.Builder
	fmt.Fprintln(&b, a.Summary)
	if p := a.Process; p != nil {
		fmt.Fprintf(&b, "\nProgram: %s (pid %d)\n", a.ExeName(), p.PID)
		if p.Image != "" {
			fmt.Fprintln(&b, p.Image)
		}
		fmt.Fprintf(&b, "Signature: %s\n", p.Signature)
		if len(p.Parents) > 0 && !p.Parents[0].Exited {
			fmt.Fprintf(&b, "Started by: %s\n", procBase(p.Parents[0].Image))
		}
	}
	for _, h := range a.Baits {
		fmt.Fprintf(&b, "\nIt %s: %s\n%s\n", accessVerb(h.Access), h.Name, h.Path)
	}
	if len(a.Actions) > 0 {
		fmt.Fprintln(&b, "\nWhat SENTIENT1 did:")
		for _, r := range a.Actions {
			if r.OK {
				fmt.Fprintf(&b, "✓ %s\n", config.Action(r.Action).Done(r.Detail))
			} else {
				fmt.Fprintf(&b, "✗ Couldn't %s: %s\n", config.Action(r.Action).Verb(), r.Detail)
			}
		}
	}
	if a.Learning {
		fmt.Fprintln(&b, "\nLearning mode: nothing was blocked. Review with `sentient1 learn`.")
	}
	return b.String()
}

// ShowPopup displays the alert and acts on the user's choice. cli is the
// installed sentient1.exe used for privileged follow-ups.
func ShowPopup(a *alerts.Alert, cli string) {
	title := "SENTIENT1: " + a.Title
	body := Details(a)
	frozen := a.Did(config.ActionFreeze) && !a.Did(config.ActionKill)
	isolated := a.Did(config.ActionIsolate) || a.Did(config.ActionDisableAdapters)

	switch {
	case a.Test:
		messageBox(title, body+"\nThis was a test. Everything worked.", mbOK|mbIconInfo)
	case frozen:
		// "Is it yours?" is the wrong question here: people who ran a cracked
		// game or a "free Nitro" tool did start it themselves. Ask whether it
		// should be reading this, and only trust signed programs in one click.
		// The question must be one where "Yes" means kill: an earlier "Did you
		// expect it to read this?" made an honest "yes" kill the program.
		oneClick := trust.OneClick(a)
		text := body + "\n" + a.ExeName() + " was frozen while reading " + baitWhat(a) + ".\n" +
			"Games, mods, cheats, cracks and \"free\" tools never need to, even ones you started yourself.\n\n" +
			"Kill it?\n" +
			"Yes = Kill it (recommended)\n"
		if oneClick {
			text += "No = It's mine: unfreeze it and trust it for this from now on\n"
		} else {
			text += "No = It's mine: unfreeze it (this time only)\n"
		}
		text += "Cancel = Decide later (it stays frozen)" + warnings(a)
		if isolated {
			text += "\n\nYour PC is isolated from the network. When it's safe, run `sentient1 release` as admin."
		}
		switch messageBox(title, text, mbYesNoCancel|mbIconError) {
		case idYes:
			if cli != "" {
				RunElevated(cli, "kill", a.ID)
			}
		case idNo:
			if cli != "" && oneClick {
				RunElevated(cli, "trust", a.ID)
			} else if cli != "" {
				RunElevated(cli, "resume", a.ID)
			}
		}
	case isolated:
		text := body + "\nYour PC is isolated from the network (SENTIENT1's own alerts still get out).\n\nYes = Restore the internet now (only if you're sure)\nNo = Keep it isolated"
		if messageBox(title, text, mbYesNo|mbIconError) == idYes {
			if cli != "" {
				RunElevated(cli, "release")
			}
		}
	case a.Kind == alerts.KindDecoyRetired || a.Process == nil || a.Process.Image == "":
		messageBox(title, body, mbOK|mbIconInfo)
	default:
		// Nothing was done to it: one click to say it's yours.
		icon := uint32(mbIconWarning)
		ask := "\nShould " + a.ExeName() + " be reading " + baitWhat(a) + "?\n\n"
		if _, why := trust.Rule(a); why == "" {
			ask += "Yes = It's mine: trust it for this, no more alerts about it\n"
		} else {
			ask += "Yes = It's mine (just this once: " + why + ")\n"
		}
		ask += "No = Not sure: keep alerting (review later with `sentient1 alerts`)" + warnings(a)
		if !a.Process.Signature.Valid || a.Tier == config.TierCritical {
			icon = mbIconError
		}
		if messageBox(title, body+ask, mbYesNo|icon) == idYes && cli != "" {
			RunElevated(cli, "trust", a.ID)
		}
	}
}

// baitWhat names what the program read, for the popup question.
func baitWhat(a *alerts.Alert) string {
	if len(a.Verdict.Swept) > 1 {
		return fmt.Sprintf("the data of %d different apps", len(a.Verdict.Swept))
	}
	if len(a.Baits) > 0 && a.Baits[0].Name != "" {
		return a.Baits[0].Name
	}
	return "this file"
}

// warnings are the red flags worth repeating next to the question.
func warnings(a *alerts.Alert) string {
	var w string
	if a.Process != nil && !a.Process.Signature.Valid {
		w += "\n\nIt isn't signed by any publisher, which is how most stealers look. Only say it's yours if you built or installed it yourself."
	}
	if len(a.Verdict.Swept) > 1 {
		w += "\n\nIt went through several apps' data one after another. That's what stealers do; real apps only touch their own."
	}
	return w
}

func accessVerb(access string) string {
	if access == "delete" {
		return "deleted"
	}
	return "read"
}

func procBase(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// toastRun is swapped in tests to capture PowerShell's output.
var toastRun = func(cmd *exec.Cmd) ([]byte, error) { return nil, cmd.Start() }

var lastToastErr string
