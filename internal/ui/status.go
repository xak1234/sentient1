package ui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/xak1234/sentient1/internal/alerts"
	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/protection"
	"github.com/xak1234/sentient1/internal/svcctl"
)

// StatusData is everything the dashboard shows (all readable without admin).
type StatusData struct {
	Cfg     *config.Config
	State   *config.State
	Service svcctl.State
	Alerts  []*alerts.Alert
	Err     error
	At      time.Time
}

func LoadStatus() StatusData {
	d := StatusData{At: time.Now()}
	d.Cfg, d.Err = config.LoadConfig()
	d.State, _ = config.LoadState()
	d.Service, _ = svcctl.Status()
	d.Alerts, _ = alerts.List(8)
	return d
}

// actionList says in plain words what happens to a reader of some tier.
func actionList(acts []config.Action) string {
	if len(acts) == 0 {
		return Dim.Render("alert only")
	}
	words := map[config.Action]string{
		config.ActionFreeze: "frozen", config.ActionBlockProgram: "internet cut", config.ActionKill: "killed",
		config.ActionIsolate: "PC isolated", config.ActionDisableAdapters: "adapters off",
	}
	var s []string
	for _, a := range acts {
		s = append(s, words[a])
	}
	return strings.Join(s, " + ")
}

// plural: "1 program", "3 programs".
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// RenderStatus draws the dashboard.
func RenderStatus(d StatusData) string {
	var b strings.Builder
	b.WriteString(Banner(Tagline) + "\n\n")
	if d.Err != nil {
		b.WriteString(Bad.Render(IconBad+" ") + d.Err.Error() + "\n\n" + Hint("Set it up with", "sentient1 install") + "\n")
		return b.String()
	}
	cfg, st := d.Cfg, d.State
	w := Width()

	// Emergency banner.
	incident := st != nil && (st.Isolation != nil || len(st.Frozen) > 0 || len(st.Blocked) > 0)
	if incident {
		var lines []string
		if st.Isolation != nil {
			lines = append(lines, fmt.Sprintf("This PC is cut off from the network since %s (alert %s).", st.Isolation.Since.Format("Jan 2 15:04"), shortID(st.Isolation.AlertID)))
		}
		if len(st.Frozen) > 0 {
			lines = append(lines, plural(len(st.Frozen), "process", "processes")+" frozen.")
		}
		if len(st.Blocked) > 0 {
			lines = append(lines, plural(len(st.Blocked), "program", "programs")+" cut off from the internet.")
		}
		lines = append(lines, "", Hint("Look at it:", "sentient1 alerts show <id>")+"     "+Hint("Undo everything when safe:", "sentient1 release"))
		box := lipgloss.NewStyle().Border(lipgloss.ThickBorder()).BorderForeground(Jaw).Padding(0, 2).Width(w - 2).
			Render(Bad.Bold(true).Render("● RESPONSE ACTIVE") + "\n" + strings.Join(lines, "\n"))
		b.WriteString(box + "\n\n")
	}

	// Protection card.
	svcOK := d.Service == svcctl.Running
	svcLine := Check(svcOK, "Service "+string(d.Service))
	if svcOK && st != nil && !st.Heartbeat.IsZero() && time.Since(st.Heartbeat) > 3*time.Minute {
		svcLine = Warn.Render(IconWarn) + " Service running, but quiet since " + Ago(st.Heartbeat)
	}
	prot := []string{svcLine}
	healthy, total := 0, 0
	if st != nil {
		for _, h := range st.Health {
			if h.Name == "Baits" || h.Name == "Network guard" {
				continue
			}
			prot = append(prot, Check(h.OK, h.Name+": "+h.Detail))
		}
		for _, bs := range st.Baits {
			if bs.Status == "retired" {
				continue
			}
			total++
			if bs.Status == "ok" {
				healthy++
			}
		}
	}
	baitsOK := total > 0 && healthy == total
	prot = append(prot, Check(baitsOK, fmt.Sprintf("%d of %d baits healthy", healthy, total)))
	if st != nil && !st.Heartbeat.IsZero() {
		prot = append(prot, Fainter.Render("last check "+Ago(st.Heartbeat)))
	}

	// Response card.
	resp := []string{Bold.Render(cfg.PresetName())}
	resp = append(resp, Dim.Render("critical    ")+actionList(cfg.Responses[config.TierCritical]))
	resp = append(resp, Dim.Render("suspicious  ")+actionList(cfg.Responses[config.TierWarn]))
	if cfg.Learning(time.Now()) && cfg.LearningMatters() {
		resp = append(resp, Warn.Render("learning, "+Until(cfg.LearningUntil))+Dim.Render(": only critical is stopped"))
	}
	if st != nil && st.Isolation != nil {
		resp = append(resp, Dim.Render("network     ")+Bad.Bold(true).Render("isolated"))
	} else {
		resp = append(resp, Dim.Render("network     ")+Good.Render("online"))
	}
	ver := "version ?"
	if st != nil && st.ServiceVersion != "" {
		ver = st.ServiceVersion
	}
	switch {
	case cfg.AutoUpdate && st != nil && st.Update != nil && !st.Update.UpdatedAt.IsZero() && time.Since(st.Update.UpdatedAt) < 7*24*time.Hour:
		ver += " · updated " + Ago(st.Update.UpdatedAt)
	case cfg.AutoUpdate:
		ver += " · auto-update on"
	default:
		ver += " · auto-update off"
	}
	resp = append(resp, Fainter.Render(ver))

	assessment := protection.Assess(true, d.Service, st, d.At)
	style := Warn
	if assessment.Level == "healthy" {
		style = Good
	}
	if assessment.Level == "inactive" || assessment.Level == "response" {
		style = Bad
	}
	status := style.Bold(true).Render("● "+assessment.Title) + Dim.Render(fmt.Sprintf("  ·  %d/%d decoys ready", assessment.Healthy, assessment.Total))
	if len(assessment.Reasons) > 0 {
		status += "\n " + Dim.Render(strings.Join(assessment.Reasons, "; "))
	}

	if !incident {
		b.WriteString(" " + status + "\n\n")
	}

	half := (w - 3) / 2
	// One row per line in the cards: cut what doesn't fit (card border and
	// padding take 6 columns).
	fit := func(lines []string, width int) string {
		for i, l := range lines {
			if lipgloss.Width(l) > width-6 {
				lines[i] = Truncate(l, width-6)
			}
		}
		return strings.Join(lines, "\n")
	}
	left := Card.Width(half).Render(Section.Render("Protection") + "\n" + fit(prot, half))
	right := Card.Width(w - 3 - half).Render(Section.Render("Response") + "\n" + fit(resp, w-3-half))
	if w < 70 {
		b.WriteString(left + "\n" + right + "\n")
	} else {
		b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right) + "\n")
	}

	// Alerts.
	b.WriteString(Heading(" Recent alerts") + "\n")
	if len(d.Alerts) == 0 {
		b.WriteString(Dim.Render("  Nothing has touched your baits yet. ") + Hint("See what a catch looks like:", "sentient1 test") + "\n")
	} else {
		b.WriteString(AlertTable(d.Alerts, w) + "\n")
	}
	return b.String()
}

// AlertTable renders a compact list of alerts.
func AlertTable(list []*alerts.Alert, w int) string {
	var b strings.Builder
	whoW := 8 // "PROGRAM", or the longest name up to 22
	for _, a := range list {
		whoW = max(whoW, min(lipgloss.Width(a.ReaderName()), 36))
	}
	whatW := w - 2 - 12 - 2 - 12 - 2 - whoW - 2 - 6
	head := fmt.Sprintf("  %-12s  %-12s  %-*s  %-*s  %s", "WHEN", "SEVERITY", whoW, "PROGRAM", whatW, "WHAT IT READ", "ID")
	b.WriteString(Fainter.Render(head) + "\n")
	for _, a := range list {
		when := a.Time.Format("Jan 02 15:04")
		what := ""
		if len(a.Baits) > 0 {
			what = a.Baits[0].Name
			if len(a.Baits) > 1 {
				what += fmt.Sprintf(" +%d more", len(a.Baits)-1)
			}
		} else {
			what = a.Title
		}
		var tags []string
		if a.Test {
			tags = append(tags, "test")
		}
		if len(a.Verdict.Swept) > 1 {
			tags = append(tags, "sweep")
		}
		if a.Learning {
			tags = append(tags, "learning")
		}
		for _, r := range a.Actions {
			if r.OK {
				tags = append(tags, map[config.Action]string{config.ActionFreeze: "frozen", config.ActionBlockProgram: "internet cut",
					config.ActionKill: "killed", config.ActionIsolate: "PC isolated", config.ActionDisableAdapters: "adapters off"}[r.Action])
			}
		}
		status := ""
		if a.Status == "resolved" {
			status = Good.Render("✓ " + a.Note)
			if a.Note == "" {
				status = Good.Render("✓ resolved")
			}
		}
		tier := lipgloss.NewStyle().Width(12).Render(TierDot(a.Tier) + " " + TierWord(a.Tier))
		who := lipgloss.NewStyle().Width(whoW).Render(Plain.Render(Truncate(a.ReaderName(), whoW)))
		whatCol := lipgloss.NewStyle().Width(whatW).Render(Truncate(what, whatW))
		b.WriteString(fmt.Sprintf("  %s  %s  %s  %s  %s\n", Dim.Render(when), tier, who, whatCol, Fainter.Render(shortID(a.ID))))
		// A second line only when there's something to say about it.
		if len(tags) > 0 || status != "" {
			sub := strings.Repeat(" ", 2+12+2+12+2)
			if len(tags) > 0 {
				sub += Dim.Render(strings.Join(tags, " · "))
				if status != "" {
					sub += Dim.Render("  ·  ")
				}
			}
			b.WriteString(sub + status + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// AlertDetail renders one alert fully.
func AlertDetail(a *alerts.Alert) string {
	var b strings.Builder
	w := Width() - 2
	wrap := func(s string, indent int) string {
		return lipgloss.NewStyle().PaddingLeft(indent).Width(w).Render(s)
	}
	b.WriteString("\n" + TierBadge(a.Tier) + " " + Bold.Render(a.Title) + "\n")
	b.WriteString(Dim.Render(a.Time.Format("Mon Jan 2 2006, 15:04:05")+"  ·  alert "+shortID(a.ID)) + "\n")
	if a.Summary != "" {
		b.WriteString("\n" + wrap(Plain.Render(a.Summary), 0) + "\n")
	}
	if a.Test {
		b.WriteString(Info.Render("This was a test run by `sentient1 test`.") + "\n")
	}
	if a.Learning {
		b.WriteString(Warn.Render("Learning mode: no action was taken. ") + Hint("Review with", "sentient1 learn") + "\n")
	}
	if len(a.Baits) > 0 {
		b.WriteString(Heading("Baits touched") + "\n")
		for _, h := range a.Baits {
			b.WriteString(fmt.Sprintf("  %s %s %s\n    %s\n", Dim.Render(h.Time.Format("15:04:05.000")), h.Access, Bold.Render(h.Name), Fainter.Render(h.Path)))
		}
	}
	if p := a.Process; p != nil {
		b.WriteString(Heading("Reader") + "\n")
		rows := [][2]string{{"Process", fmt.Sprintf("%s (pid %d)", a.ReaderName(), p.PID)}}
		if p.Image != "" {
			rows = append(rows, [2]string{"Path", p.Image})
		}
		sig := p.Signature.String()
		if p.Signature.Valid {
			sig = Good.Render(sig)
		} else {
			sig = Bad.Render(sig)
		}
		rows = append(rows, [2]string{"Signature", sig})
		if p.CommandLine != "" {
			rows = append(rows, [2]string{"Command", Truncate(p.CommandLine, Width()-14)})
		}
		if p.User != "" {
			rows = append(rows, [2]string{"User", p.User})
		}
		if p.SHA256 != "" {
			rows = append(rows, [2]string{"SHA-256", p.SHA256})
		}
		for i, par := range p.Parents {
			label := "Parent"
			if i > 0 {
				label = strings.Repeat(" ", 2*i) + "└ parent"
			}
			v := fmt.Sprintf("pid %d (exited)", par.PID)
			if !par.Exited {
				v = fmt.Sprintf("%s (pid %d)", par.Image, par.PID)
			}
			rows = append(rows, [2]string{label, v})
		}
		b.WriteString(indent(KV(rows), 2) + "\n")
		if p.Hosted != nil {
			b.WriteString(Heading("Hosted component") + "\n" + indent(p.Hosted.Details(), 2) + "\n")
		}
		if len(p.Connections) > 0 {
			// What matters is anything talking to another machine; listening
			// sockets and connections to this PC itself are summarised.
			local := 0
			var order []string
			count := map[string]int{}
			for _, c := range p.Connections {
				r := c.Remote
				if r == "" || c.State == "LISTEN" || strings.HasPrefix(r, "0.0.0.0") || strings.HasPrefix(r, "[::]") ||
					strings.HasPrefix(r, "127.") || strings.HasPrefix(r, "[::1]") {
					local++
					continue
				}
				key := c.Proto + " " + r
				if count[key] == 0 {
					order = append(order, key)
				}
				count[key]++
			}
			var remote []string
			for i, k := range order {
				if i == 8 {
					remote = append(remote, Fainter.Render(fmt.Sprintf("  + %d more destinations", len(order)-8)))
					break
				}
				proto, addr, _ := strings.Cut(k, " ")
				line := "  " + Dim.Render(fmt.Sprintf("%-4s", proto)) + " → " + Bold.Render(addr)
				if n := count[k]; n > 1 {
					line += Fainter.Render(fmt.Sprintf("  ×%d", n))
				}
				remote = append(remote, line)
			}
			b.WriteString(Heading("Network at detection") + "\n")
			for _, l := range remote {
				b.WriteString(l + "\n")
			}
			switch {
			case len(remote) == 0:
				b.WriteString("  " + Good.Render("no connections to other machines") + Fainter.Render(fmt.Sprintf("  (%d local)", local)) + "\n")
			case local > 0:
				b.WriteString(Fainter.Render(fmt.Sprintf("  + %d local or listening", local)) + "\n")
			}
		}
	}
	if len(a.Verdict.Reasons) > 0 {
		b.WriteString(Heading("Why this severity") + "\n")
		for _, r := range a.Verdict.Reasons {
			lines := strings.Split(lipgloss.NewStyle().Width(w-4).Render(r), "\n")
			for i, l := range lines {
				mark := "  "
				if i == 0 {
					mark = Dim.Render(IconDot) + " "
				}
				b.WriteString("  " + mark + l + "\n")
			}
		}
	}
	if len(a.Actions) > 0 {
		b.WriteString(Heading("Response") + "\n")
		for _, r := range a.Actions {
			b.WriteString("  " + Check(r.OK, r.Action.Describe()) + "\n")
			if r.Detail != "" {
				b.WriteString(wrap(Fainter.Render(r.Detail), 4) + "\n")
			}
		}
		if a.LatencyMS > 0 {
			when := "after the read was logged"
			if a.Instant {
				when = "after it opened the bait, before it could read it"
			}
			b.WriteString("  " + Good.Render(fmt.Sprintf("%d ms", a.LatencyMS)) + Dim.Render(" "+when) + "\n")
		}
	}
	if a.Status == "resolved" {
		b.WriteString("\n" + Good.Render(IconOK+" Resolved: "+a.Note) + "\n")
	} else if a.Process != nil && !a.Test && a.Kind == alerts.KindRead {
		id := shortID(a.ID)
		var rows [][2]string
		if a.Did(config.ActionFreeze) || a.Did(config.ActionBlockProgram) {
			rows = append(rows, [2]string{"sentient1 kill " + id, "it's malware: end it (it stays cut off)"})
		}
		rows = append(rows, [2]string{"sentient1 trust " + id, "it's yours: undo everything and stop alerting about it"})
		if a.Did(config.ActionFreeze) || a.Did(config.ActionBlockProgram) {
			rows = append(rows, [2]string{"sentient1 resume " + id, "not sure: let it run again, without trusting it"})
		}
		if a.Did(config.ActionIsolate) {
			rows = append(rows, [2]string{"sentient1 release", "reconnect the PC when it's safe"})
		}
		b.WriteString(Heading("What now") + "\n" + indent(Cmd(rows), 2) + "\n")
	}
	if a.Tier == config.TierCritical && !a.Test && a.Status != "resolved" {
		b.WriteString(Heading("If you didn't cause this") + "\n")
		for i, s := range alerts.Checklist(a) {
			b.WriteString(lipgloss.NewStyle().PaddingLeft(5).Width(Width() - 2).Render(fmt.Sprintf("%d. %s", i+1, s))[3:] + "\n")
		}
	}
	return b.String()
}

func shortID(id string) string {
	if i := strings.LastIndex(id, "-"); i > 0 {
		return id[i+1:]
	}
	return id
}

func indent(s string, n int) string {
	pad := strings.Repeat(" ", n)
	return pad + strings.ReplaceAll(s, "\n", "\n"+pad)
}

// ---- live dashboard ----

type tickMsg time.Time

type statusModel struct {
	data StatusData
}

func (m statusModel) Init() tea.Cmd { return tick() }

func tick() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m statusModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		case "r":
			m.data = LoadStatus()
		}
	case tickMsg:
		m.data = LoadStatus()
		return m, tick()
	case tea.WindowSizeMsg:
		return m, nil
	}
	return m, nil
}

func (m statusModel) View() string {
	return RenderStatus(m.data) + "\n" + Fainter.Render("  q quit · r refresh · live, updates every 2s") + "\n"
}

// RunDashboard shows the live dashboard (or a single snapshot without a TTY).
func RunDashboard(once bool) error {
	d := LoadStatus()
	if once || !IsTTY() {
		fmt.Print(RenderStatus(d))
		return nil
	}
	_, err := tea.NewProgram(statusModel{data: d}, tea.WithAltScreen()).Run()
	return err
}
