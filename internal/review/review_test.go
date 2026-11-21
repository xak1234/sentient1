package review

import (
	"bytes"
	"github.com/xak1234/sentient1/internal/alerts"
	"github.com/xak1234/sentient1/internal/procinfo"
	"strings"
	"testing"
)

func TestExportEscapesEvidenceAndRemovesCommands(t *testing.T) {
	d := Snapshot{Alerts: []*alerts.Alert{{Title: `<script>alert(1)</script>`, Process: &alerts.Process{CommandLine: "SECRET", Parents: []procinfo.Parent{{CommandLine: "PARENTSECRET"}}}}}}
	out, err := ForExport(d, false)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := WriteHTML(&b, out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "<script>") || strings.Contains(b.String(), "SECRET") {
		t.Fatal("unsafe or private evidence in HTML")
	}
	if !strings.Contains(b.String(), "&lt;script&gt;") {
		t.Fatal("escaped evidence missing")
	}
	if d.Alerts[0].Process.CommandLine != "SECRET" {
		t.Fatal("export mutated original evidence")
	}
	if out.Alerts[0].Process.Parents[0].CommandLine != "" {
		t.Fatal("parent command line leaked")
	}
}
