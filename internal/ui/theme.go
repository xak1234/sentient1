// Package ui holds SENTIENT1's terminal look: colours, layout helpers, the
// install wizard, the live status dashboard and the step runner.
//
// One palette everywhere: green for "protected / yes / go", red for danger,
// amber for "look at this", sky for information, and two greys for
// secondary text. Everything adapts to light terminals.
package ui

import (
	crand "crypto/rand"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"golang.org/x/term"

	"github.com/xak1234/sentient1/internal/config"
)

var (
	Leaf   = lipgloss.AdaptiveColor{Light: "#1E8A4C", Dark: "#7BD88F"}
	Jaw    = lipgloss.AdaptiveColor{Light: "#C4314B", Dark: "#FF6B85"}
	Amber  = lipgloss.AdaptiveColor{Light: "#B26B00", Dark: "#FFC66D"}
	Sky    = lipgloss.AdaptiveColor{Light: "#1F6FB2", Dark: "#7CC4FF"}
	Muted  = lipgloss.AdaptiveColor{Light: "#5B6472", Dark: "#9AA3B2"}
	Faint  = lipgloss.AdaptiveColor{Light: "#9CA3AF", Dark: "#5C6370"}
	Border = lipgloss.AdaptiveColor{Light: "#D1D5DB", Dark: "#3B4252"}
	Text   = lipgloss.AdaptiveColor{Light: "#111827", Dark: "#E5E9F0"}
	Ink    = lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#0B1F12"} // text on a green fill
	Shade  = lipgloss.AdaptiveColor{Light: "#E5E7EB", Dark: "#2A303B"} // quiet fills (blurred buttons, empty bar)

	Bold    = lipgloss.NewStyle().Bold(true).Foreground(Text)
	Plain   = lipgloss.NewStyle().Foreground(Text)
	Dim     = lipgloss.NewStyle().Foreground(Muted)
	Fainter = lipgloss.NewStyle().Foreground(Faint)
	Good    = lipgloss.NewStyle().Foreground(Leaf)
	Bad     = lipgloss.NewStyle().Foreground(Jaw)
	Warn    = lipgloss.NewStyle().Foreground(Amber)
	Info    = lipgloss.NewStyle().Foreground(Sky)
	Code    = lipgloss.NewStyle().Foreground(Leaf).Bold(true)
	Title   = lipgloss.NewStyle().Bold(true).Foreground(Text).MarginBottom(1)
	Section = lipgloss.NewStyle().Bold(true).Foreground(Leaf)

	Card = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(Border).Padding(0, 2)
)

const (
	IconOK   = "✓"
	IconBad  = "✗"
	IconWarn = "!"
	IconDot  = "•"
	IconArr  = "›"
)

// IsTTY reports whether stdout is an interactive terminal.
func IsTTY() bool { return term.IsTerminal(int(os.Stdout.Fd())) }

// ForceWidth fixes the layout width (previews and tests); 0 = the terminal's.
var ForceWidth int

// Width of the terminal (80 if unknown), capped for readability.
func Width() int {
	if ForceWidth > 0 {
		return ForceWidth
	}
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 {
		return 80
	}
	if w > 100 {
		return 100
	}
	return w
}

// ---- logo ----

// The wordmark: "SENTIENT1" in half-block letters, two rows tall.
var logoRows = [2]string{"sentient1", "DECOY DEFENCE"}

// Logo renders the wordmark with a soft green gradient.
func Logo() []string {
	from, to := [3]float64{0x9B, 0xF0, 0xAA}, [3]float64{0x3F, 0xB8, 0xAF}
	if !lipgloss.HasDarkBackground() {
		from, to = [3]float64{0x1E, 0x8A, 0x4C}, [3]float64{0x0F, 0x76, 0x6E}
	}
	var out []string
	for _, row := range logoRows {
		runes := []rune(row)
		var b strings.Builder
		for i, r := range runes {
			if r == ' ' {
				b.WriteRune(r)
				continue
			}
			t := float64(i) / float64(len(runes)-1)
			c := fmt.Sprintf("#%02X%02X%02X", lerp(from[0], to[0], t), lerp(from[1], to[1], t), lerp(from[2], to[2], t))
			b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(c)).Render(string(r)))
		}
		out = append(out, b.String())
	}
	return out
}

func lerp(a, b, t float64) int { return int(a + (b-a)*t + 0.5) }

// Banner is the two-line header on every interactive screen: the wordmark,
// the name, and what this screen is.
func Banner(subtitle string) string {
	logo := Logo()
	name := Bold.Render("sentient1")
	return " " + logo[0] + "   " + name + "\n" + " " + logo[1] + "   " + Dim.Render(subtitle)
}

// ---- building blocks ----

// TierBadge renders a coloured tier label.
func TierBadge(t config.Tier) string {
	s := lipgloss.NewStyle().Bold(true).Padding(0, 1)
	switch t {
	case config.TierCritical:
		return s.Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#D7263D")).Render("CRITICAL")
	case config.TierWarn:
		return s.Foreground(lipgloss.Color("#1A1A1A")).Background(lipgloss.Color("#FFB000")).Render("SUSPICIOUS")
	case config.TierInfo:
		return s.Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#3B82F6")).Render("INFO")
	}
	return s.Render(strings.ToUpper(string(t)))
}

// TierWord is a coloured tier name without a background (for tables).
func TierWord(t config.Tier) string {
	switch t {
	case config.TierCritical:
		return Bad.Bold(true).Render("critical")
	case config.TierWarn:
		return Warn.Render("suspicious")
	}
	return Info.Render("info")
}

// TierDot is a small coloured marker for a tier.
func TierDot(t config.Tier) string {
	switch t {
	case config.TierCritical:
		return Bad.Render("●")
	case config.TierWarn:
		return Warn.Render("●")
	}
	return Info.Render("●")
}

// Check renders ✓/✗ with a label.
func Check(ok bool, label string) string {
	if ok {
		return Good.Render(IconOK) + " " + label
	}
	return Bad.Render(IconBad) + " " + label
}

// KV renders aligned key/value rows.
func KV(rows [][2]string) string {
	w := 0
	for _, r := range rows {
		if l := lipgloss.Width(r[0]); l > w {
			w = l
		}
	}
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(Dim.Render(fmt.Sprintf("%-*s", w, r[0])) + "  " + r[1] + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// Bar renders a thin progress bar of width cells, done/total filled.
func Bar(done, total, width int) string {
	if total <= 0 || width <= 0 {
		return ""
	}
	n := done * width / total
	return Good.Render(strings.Repeat("━", n)) + lipgloss.NewStyle().Foreground(Shade).Render(strings.Repeat("━", width-n))
}

// Rule is a faint horizontal line.
func Rule(width int) string {
	return lipgloss.NewStyle().Foreground(Border).Render(strings.Repeat("─", width))
}

// Callout is an amber "heads up" line with a ! marker, wrapped to width.
func Callout(text string, width int) string {
	body := lipgloss.NewStyle().Width(width - 2).Foreground(Text).Render(text)
	lines := strings.Split(body, "\n")
	for i := range lines {
		if i == 0 {
			lines[i] = Warn.Bold(true).Render("!") + " " + lines[i]
		} else {
			lines[i] = "  " + lines[i]
		}
	}
	return strings.Join(lines, "\n")
}

// Ago formats a time relative to now.
func Ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

// Until formats a remaining duration.
func Until(t time.Time) string {
	d := time.Until(t)
	if d <= 0 {
		return "ended"
	}
	if d > 48*time.Hour {
		return fmt.Sprintf("%d days left", int(d.Hours()/24+0.5))
	}
	if d > time.Hour {
		return fmt.Sprintf("%dh left", int(d.Hours()))
	}
	return fmt.Sprintf("%dm left", int(d.Minutes())+1)
}

// Truncate shortens s to n display cells with an ellipsis. Colour codes in s
// are kept intact (and closed), so a styled string can be cut too.
func Truncate(s string, n int) string {
	if n <= 1 || lipgloss.Width(s) <= n {
		return s
	}
	return ansi.Truncate(s, n, "…")
}

// TruncateMiddle keeps the start and end of a path.
func TruncateMiddle(s string, n int) string {
	r := []rune(s)
	if len(r) <= n || n < 8 {
		return s
	}
	keep := (n - 1) / 2
	return string(r[:keep]) + "…" + string(r[len(r)-(n-1-keep):])
}

// Println prints with a trailing newline.
func Println(s ...string) { fmt.Println(strings.Join(s, " ")) }

// Fail prints an error line.
func Fail(err error) {
	fmt.Fprintln(os.Stderr, "\n"+Bad.Bold(true).Render(IconBad+" ")+Plain.Render(err.Error()))
}

// Hint prints a dim hint with a highlighted command.
func Hint(text, cmd string) string {
	return Dim.Render(text+" ") + Code.Render(cmd)
}

// Cmd lists commands with what they do, aligned:  sentient1 test   watch it…
func Cmd(rows [][2]string) string {
	w := 0
	for _, r := range rows {
		if l := lipgloss.Width(r[0]); l > w {
			w = l
		}
	}
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(Code.Render(fmt.Sprintf("%-*s", w, r[0])) + "   " + Dim.Render(r[1]) + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func randByte() byte {
	var b [1]byte
	crand.Read(b[:])
	return b[0]
}

// Heading is a section title preceded by a blank line.
func Heading(s string) string { return "\n" + Section.Render(s) }

// Tagline is the one-liner shown under the name.
const Tagline = "decoy defence. evidence first."

// ---- forms ----

// Theme is the look of every question SENTIENT1 asks (huh forms), in SENTIENT1's palette.
func Theme() *huh.Theme {
	t := huh.ThemeBase()
	button := lipgloss.NewStyle().Padding(0, 2).MarginRight(1)

	f := &t.Focused
	f.Base = lipgloss.NewStyle().PaddingLeft(2).BorderStyle(lipgloss.ThickBorder()).BorderLeft(true).BorderForeground(Leaf)
	f.Card = f.Base
	f.Title = lipgloss.NewStyle().Foreground(Text).Bold(true)
	f.NoteTitle = lipgloss.NewStyle().Foreground(Leaf).Bold(true).MarginBottom(1)
	f.Description = lipgloss.NewStyle().Foreground(Muted)
	f.ErrorIndicator = lipgloss.NewStyle().Foreground(Jaw).SetString(" *")
	f.ErrorMessage = lipgloss.NewStyle().Foreground(Jaw)
	f.SelectSelector = lipgloss.NewStyle().Foreground(Leaf).Bold(true).SetString("› ")
	f.NextIndicator = lipgloss.NewStyle().Foreground(Leaf).MarginLeft(1).SetString("→")
	f.PrevIndicator = lipgloss.NewStyle().Foreground(Leaf).MarginRight(1).SetString("←")
	f.Option = lipgloss.NewStyle().Foreground(Text)
	f.MultiSelectSelector = lipgloss.NewStyle().Foreground(Leaf).Bold(true).SetString("› ")
	f.SelectedOption = lipgloss.NewStyle().Foreground(Text)
	f.SelectedPrefix = lipgloss.NewStyle().Foreground(Leaf).Bold(true).SetString("✓ ")
	f.UnselectedOption = lipgloss.NewStyle().Foreground(Muted)
	f.UnselectedPrefix = lipgloss.NewStyle().Foreground(Faint).SetString("· ")
	f.TextInput.Cursor = lipgloss.NewStyle().Foreground(Leaf)
	f.TextInput.CursorText = lipgloss.NewStyle().Foreground(Text)
	f.TextInput.Placeholder = lipgloss.NewStyle().Foreground(Faint)
	f.TextInput.Prompt = lipgloss.NewStyle().Foreground(Leaf)
	f.TextInput.Text = lipgloss.NewStyle().Foreground(Text)
	f.FocusedButton = button.Foreground(Ink).Background(Leaf).Bold(true)
	f.BlurredButton = button.Foreground(Muted).Background(Shade)
	f.Next = f.FocusedButton

	t.Blurred = t.Focused
	t.Blurred.Base = f.Base.BorderStyle(lipgloss.HiddenBorder())
	t.Blurred.Card = t.Blurred.Base
	t.Blurred.Title = lipgloss.NewStyle().Foreground(Muted)
	t.Blurred.MultiSelectSelector = lipgloss.NewStyle().SetString("  ")
	t.Blurred.SelectSelector = lipgloss.NewStyle().SetString("  ")
	t.Blurred.NextIndicator = lipgloss.NewStyle()
	t.Blurred.PrevIndicator = lipgloss.NewStyle()

	t.Group.Title = f.Title
	t.Group.Description = f.Description

	t.Help.ShortKey = lipgloss.NewStyle().Foreground(Muted)
	t.Help.ShortDesc = lipgloss.NewStyle().Foreground(Faint)
	t.Help.ShortSeparator = lipgloss.NewStyle().Foreground(Faint)
	t.Help.FullKey = t.Help.ShortKey
	t.Help.FullDesc = t.Help.ShortDesc
	t.Help.FullSeparator = t.Help.ShortSeparator
	return t
}
