//go:build preview

// Command uipreview renders every SENTIENT1 screen to PNG for design review:
//
//	go run -tags preview ./scripts/uipreview -out <dir> [-width 100] [-light]
//
// Each screen is rendered with true colour, converted from ANSI to HTML in a
// Windows Terminal look (Cascadia Mono, Campbell colours) and screenshotted
// with headless Microsoft Edge. Dev tool only; not part of SENTIENT1.
package main

import (
	"flag"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/xak1234/sentient1/internal/cli"
	"github.com/xak1234/sentient1/internal/ui"
)

func main() {
	out := flag.String("out", "uipreview", "output folder")
	width := flag.Int("width", 100, "terminal width in columns")
	light := flag.Bool("light", false, "light terminal background")
	only := flag.String("only", "", "only screens whose name contains this")
	scale := flag.Int("scale", 1, "device scale factor (2 for crisp README images)")
	flag.Parse()

	lipgloss.SetColorProfile(termenv.TrueColor)
	lipgloss.SetHasDarkBackground(!*light)
	ui.ForceWidth = *width
	os.MkdirAll(*out, 0o755)

	edge := `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`
	bg, fg := "#0C0C0C", "#CCCCCC"
	if *light {
		bg, fg = "#F7F7F7", "#1F2328"
	}
	for _, s := range cli.Previews() {
		if *only != "" && !strings.Contains(s.Name, *only) {
			continue
		}
		lines := strings.Split(strings.TrimRight(s.ANSI, "\n"), "\n")
		page := fmt.Sprintf(`<!doctype html><meta charset="utf-8"><style>
html,body{margin:0;background:%s}
pre{margin:0;padding:18px 22px;font:15px/18px "Cascadia Mono","Cascadia Code",Consolas,monospace;color:%s;white-space:pre}
</style><pre>%s</pre>`, bg, fg, toHTML(s.ANSI))
		htmlPath, _ := filepath.Abs(filepath.Join(*out, s.Name+".html"))
		pngPath, _ := filepath.Abs(filepath.Join(*out, s.Name+".png"))
		os.WriteFile(htmlPath, []byte(page), 0o644)
		w := *width*9 + 50
		h := len(lines)*18 + 40
		cmd := exec.Command(edge, "--headless=new", "--disable-gpu", "--hide-scrollbars", fmt.Sprintf("--force-device-scale-factor=%d", *scale),
			"--screenshot="+pngPath, fmt.Sprintf("--window-size=%d,%d", w, h), "file:///"+filepath.ToSlash(htmlPath))
		if b, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintln(os.Stderr, s.Name, err, string(b))
			continue
		}
		fmt.Println(pngPath)
	}
}

var sgr = regexp.MustCompile(`\x1b\[([0-9;?]*)([A-Za-z])`)

var basic = []string{"#0C0C0C", "#C50F1F", "#13A10E", "#C19C00", "#0037DA", "#881798", "#3A96DD", "#CCCCCC",
	"#767676", "#E74856", "#16C60C", "#F9F1A5", "#3B78FF", "#B4009E", "#61D6D6", "#F2F2F2"}

type attr struct {
	fg, bg                     string
	bold, faint, italic, under bool
}

func (a attr) css() string {
	var s []string
	if a.fg != "" {
		s = append(s, "color:"+a.fg)
	}
	if a.bg != "" {
		s = append(s, "background:"+a.bg)
	}
	if a.bold {
		s = append(s, "font-weight:bold")
	}
	if a.faint {
		s = append(s, "opacity:.6")
	}
	if a.italic {
		s = append(s, "font-style:italic")
	}
	if a.under {
		s = append(s, "text-decoration:underline")
	}
	return strings.Join(s, ";")
}

func color256(n int) string {
	switch {
	case n < 16:
		return basic[n]
	case n < 232:
		n -= 16
		c := func(v int) int {
			if v == 0 {
				return 0
			}
			return 55 + v*40
		}
		return fmt.Sprintf("#%02X%02X%02X", c(n/36), c(n/6%6), c(n%6))
	}
	v := 8 + (n-232)*10
	return fmt.Sprintf("#%02X%02X%02X", v, v, v)
}

func toHTML(s string) string {
	var b strings.Builder
	var cur attr
	open := false
	emit := func(text string) {
		if text == "" {
			return
		}
		if css := cur.css(); css != "" {
			b.WriteString(`<span style="` + css + `">` + html.EscapeString(text) + `</span>`)
		} else {
			b.WriteString(html.EscapeString(text))
		}
	}
	_ = open
	last := 0
	for _, m := range sgr.FindAllStringSubmatchIndex(s, -1) {
		emit(s[last:m[0]])
		last = m[1]
		if s[m[4]:m[5]] != "m" {
			continue
		}
		params := strings.Split(s[m[2]:m[3]], ";")
		for i := 0; i < len(params); i++ {
			n, _ := strconv.Atoi(params[i])
			switch {
			case params[i] == "" || n == 0:
				cur = attr{}
			case n == 1:
				cur.bold = true
			case n == 2:
				cur.faint = true
			case n == 3:
				cur.italic = true
			case n == 4:
				cur.under = true
			case n == 22:
				cur.bold, cur.faint = false, false
			case n == 23:
				cur.italic = false
			case n == 24:
				cur.under = false
			case n == 39:
				cur.fg = ""
			case n == 49:
				cur.bg = ""
			case n >= 30 && n <= 37:
				cur.fg = basic[n-30]
			case n >= 90 && n <= 97:
				cur.fg = basic[n-90+8]
			case n >= 40 && n <= 47:
				cur.bg = basic[n-40]
			case n >= 100 && n <= 107:
				cur.bg = basic[n-100+8]
			case (n == 38 || n == 48) && i+1 < len(params):
				var c string
				if params[i+1] == "2" && i+4 < len(params) {
					r, _ := strconv.Atoi(params[i+2])
					g, _ := strconv.Atoi(params[i+3])
					bl, _ := strconv.Atoi(params[i+4])
					c = fmt.Sprintf("#%02X%02X%02X", r, g, bl)
					i += 4
				} else if params[i+1] == "5" && i+2 < len(params) {
					k, _ := strconv.Atoi(params[i+2])
					c = color256(k)
					i += 2
				}
				if n == 38 {
					cur.fg = c
				} else {
					cur.bg = c
				}
			}
		}
	}
	emit(s[last:])
	return b.String()
}
