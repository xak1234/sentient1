//go:build preview

package ui

import (
	"reflect"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
)

// PreviewWizard renders every page the wizard would show for the given mode
// ("recommended", "custom", "keep"), with phone set to phoneKind.
func PreviewWizard(in WizardInput, mode, phoneKind string) []string {
	w := newWizard(in)
	if w.setMode != nil {
		w.setMode(mode, phoneKind)
	}
	f := w.form
	drain(f, f.Init(), 0)
	f.Update(tea.WindowSizeMsg{Width: Width(), Height: 40})
	var views []string
	seen := map[string]bool{}
	for i := 0; i < 40; i++ {
		v := f.View()
		if !seen[v] {
			views = append(views, v)
			seen[v] = true
		}
		before := v
		drain(f, f.NextGroup(), 0)
		if f.State != huh.StateNormal || f.View() == before {
			break
		}
	}
	return views
}

// drain runs the commands a form returns (skipping slow ones such as cursor
// blinks) and feeds their messages back, so group changes take effect.
func drain(f *huh.Form, cmd tea.Cmd, depth int) {
	if cmd == nil || depth > 30 {
		return
	}
	ch := make(chan tea.Msg, 1)
	go func() { ch <- cmd() }()
	var msg tea.Msg
	select {
	case msg = <-ch:
	case <-time.After(30 * time.Millisecond):
		return
	}
	if msg == nil {
		return
	}
	if b, ok := msg.(tea.BatchMsg); ok {
		for _, c := range b {
			drain(f, c, depth+1)
		}
		return
	}
	if v := reflect.ValueOf(msg); v.Kind() == reflect.Slice && v.Type().Elem() == reflect.TypeOf(tea.Cmd(nil)) {
		for i := 0; i < v.Len(); i++ {
			drain(f, v.Index(i).Interface().(tea.Cmd), depth+1)
		}
		return
	}
	_, next := f.Update(msg)
	drain(f, next, depth+1)
}

// PreviewStep is one row for PreviewSteps: state is pending, running, done,
// warned or failed.
type PreviewStep struct{ Name, State, Detail string }

// PreviewSteps renders the progress view.
func PreviewSteps(title string, steps []PreviewStep, ended time.Duration) string {
	var rows []stepRow
	cur := 0
	for i, s := range steps {
		st := map[string]stepState{"pending": pending, "running": running, "done": done, "warned": warned, "failed": failed}[s.State]
		if st == running {
			cur = i
		}
		rows = append(rows, stepRow{name: s.Name, state: st, detail: s.Detail})
	}
	return renderSteps(title, rows, Good.Render("⠹"), cur, ended, false)
}
