package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/xak1234/sentient1/internal/install"
)

type stepState int

const (
	pending stepState = iota
	running
	done
	warned
	failed
)

type stepRow struct {
	name   string
	state  stepState
	detail string
	took   time.Duration
}

type stepsModel struct {
	title   string
	steps   []install.Step
	rows    []stepRow
	cur     int
	spin    spinner.Model
	started time.Time
	ended   time.Duration
	err     error
	quit    bool
}

type stepDone struct {
	detail string
	err    error
	took   time.Duration
}

func (m stepsModel) Init() tea.Cmd { return tea.Batch(m.spin.Tick, m.runCurrent()) }

func (m stepsModel) runCurrent() tea.Cmd {
	if m.cur >= len(m.steps) {
		return nil
	}
	st := m.steps[m.cur]
	return func() tea.Msg {
		t := time.Now()
		d, err := st.Run()
		return stepDone{d, err, time.Since(t)}
	}
}

func (m stepsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			m.err, m.quit = fmt.Errorf("cancelled"), true
			return m, tea.Quit
		}
	case spinner.TickMsg:
		var c tea.Cmd
		m.spin, c = m.spin.Update(msg)
		return m, c
	case stepDone:
		r := &m.rows[m.cur]
		r.detail, r.took = msg.detail, msg.took
		switch {
		case msg.err == nil:
			r.state = done
		case m.steps[m.cur].Soft:
			r.state, r.detail = warned, msg.err.Error()
		default:
			r.state, r.detail = failed, msg.err.Error()
			m.err, m.quit, m.ended = fmt.Errorf("%s: %w", r.name, msg.err), true, time.Since(m.started)
			return m, tea.Quit
		}
		m.cur++
		if m.cur >= len(m.steps) {
			m.quit, m.ended = true, time.Since(m.started)
			return m, tea.Quit
		}
		m.rows[m.cur].state = running
		return m, m.runCurrent()
	}
	return m, nil
}

func (m stepsModel) View() string {
	return renderSteps(m.title, m.rows, m.spin.View(), m.cur, m.ended, m.err != nil)
}

// renderSteps draws the title, a progress bar and one line per step:
// the step on the left, what it did on the right (wrapped below if long).
func renderSteps(title string, rows []stepRow, spin string, cur int, ended time.Duration, failedRun bool) string {
	w := Width() - 2
	var b strings.Builder

	doneN := 0
	for _, r := range rows {
		if r.state == done || r.state == warned {
			doneN++
		}
	}
	count := fmt.Sprintf("%d/%d", doneN, len(rows))
	if ended > 0 && !failedRun {
		count = fmt.Sprintf("done in %.1fs", ended.Seconds())
	}
	b.WriteString(" " + Bold.Render(title) + "\n")
	barW := w - 3 - lipgloss.Width(count)
	if barW > 60 {
		barW = 60
	}
	b.WriteString(" " + Bar(doneN, len(rows), barW) + "  " + Dim.Render(count) + "\n\n")

	nameW := 0
	for _, r := range rows {
		if l := lipgloss.Width(r.name); l > nameW {
			nameW = l
		}
	}
	for _, r := range rows {
		var icon string
		name := fmt.Sprintf("%-*s", nameW, r.name)
		switch r.state {
		case pending:
			icon, name = Fainter.Render("·"), Fainter.Render(name)
		case running:
			icon, name = spin, Plain.Render(name)
		case done:
			icon, name = Good.Render(IconOK), Plain.Render(name)
		case warned:
			icon, name = Warn.Render(IconWarn), Plain.Render(name)
		case failed:
			icon, name = Bad.Render(IconBad), Bad.Render(name)
		}
		line := " " + icon + " " + name
		detail := r.detail
		if r.state == done && r.took > 1500*time.Millisecond {
			if detail != "" {
				detail += " · "
			}
			detail += fmt.Sprintf("%.1fs", r.took.Seconds())
		}
		style := Dim
		switch r.state {
		case failed:
			style = Bad
		case warned:
			style = Warn
		}
		room := w - lipgloss.Width(line) - 3
		switch {
		case detail == "" || r.state == pending:
			b.WriteString(line + "\n")
		case lipgloss.Width(detail) <= room:
			b.WriteString(line + "   " + style.Render(detail) + "\n")
		default:
			b.WriteString(line + "\n" + lipgloss.NewStyle().PaddingLeft(5).Width(w).Render(style.Render(detail)) + "\n")
		}
	}
	return b.String()
}

// RunSteps executes steps with live progress. Without a TTY it prints plainly.
func RunSteps(title string, steps []install.Step) error {
	if len(steps) == 0 {
		return nil
	}
	if !IsTTY() {
		fmt.Println(title)
		for _, s := range steps {
			d, err := s.Run()
			switch {
			case err == nil:
				fmt.Printf("%s %s %s\n", IconOK, s.Name, d)
			case s.Soft:
				fmt.Printf("%s %s: %v\n", IconWarn, s.Name, err)
			default:
				fmt.Printf("%s %s: %v\n", IconBad, s.Name, err)
				return fmt.Errorf("%s: %w", s.Name, err)
			}
		}
		return nil
	}
	sp := spinner.New(spinner.WithSpinner(spinner.MiniDot), spinner.WithStyle(lipgloss.NewStyle().Foreground(Leaf)))
	m := stepsModel{title: title, steps: steps, spin: sp, started: time.Now()}
	for _, s := range steps {
		m.rows = append(m.rows, stepRow{name: s.Name})
	}
	m.rows[0].state = running
	out, err := tea.NewProgram(m).Run()
	if err != nil {
		return err
	}
	return out.(stepsModel).err
}
