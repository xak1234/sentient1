package ui

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"

	"github.com/xak1234/sentient1/internal/baits"
	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/install"
	"github.com/xak1234/sentient1/internal/paths"
)

// WizardInput is what the wizard knows before asking.
type WizardInput struct {
	User     config.UserInfo
	Plan     []baits.Availability
	Existing *config.Config  // nil on first install
	Secrets  *config.Secrets // may be empty
	Change   bool            // `sentient1 configure`: start on "Change settings"
}

// Setup modes. A first install offers Recommended (three questions) or
// Customize (everything); a re-run offers Keep (repair/upgrade with the
// current settings) or Customize.
const (
	modeRecommended = "recommended"
	modeCustom      = "custom"
	modeKeep        = "keep"
)

// wizard is the setup form plus what turns its answers into install options.
type wizard struct {
	form    *huh.Form
	finish  func() (install.Options, bool)
	setMode func(mode, phone string) // previews: walk a given path
}

// RunWizard asks everything and returns install options. ok=false if cancelled.
func RunWizard(in WizardInput) (install.Options, bool, error) {
	w := newWizard(in)
	if err := w.form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return install.Options{}, false, nil
		}
		return install.Options{}, false, err
	}
	o, ok := w.finish()
	return o, ok, nil
}

func newWizard(in WizardInput) *wizard {
	ex := in.Existing
	sec := in.Secrets
	if sec == nil {
		sec = &config.Secrets{}
	}
	o := install.Options{CleanRecent: true, Preset: "balanced", LearningDays: 3, PhoneMinTier: config.TierWarn}
	mode := modeRecommended
	if ex != nil {
		mode = modeKeep
		if in.Change {
			mode = modeCustom
		}
		o.Preset, o.CleanRecent, o.PhoneMinTier, o.KeepLearning, o.LearningDays = ex.Preset, ex.CleanRecent, ex.PhoneMinTier, true, 0
		for _, b := range ex.Baits {
			if b.Path != "" {
				o.CustomBaits = append(o.CustomBaits, b.Path)
			}
		}
	}

	// ---- baits ----
	existing := map[string]bool{}
	if ex != nil {
		for _, b := range ex.Baits {
			existing[b.ID] = true
		}
	}
	formW := min(Width()-2, 96)
	var opts []huh.Option[string]
	var skipped []string
	nameW := 0
	for _, a := range in.Plan {
		if a.Available && len(a.Spec.Name) > nameW {
			nameW = len(a.Spec.Name)
		}
	}
	// One line per bait: name, then its note cut to what fits (border,
	// cursor and tick take 7 columns).
	noteW := formW - 7 - nameW - 2
	for _, a := range in.Plan {
		if !a.Available {
			skipped = append(skipped, a.Spec.Name+" ("+a.Reason+")")
			continue
		}
		pre := a.Spec.Default
		if ex != nil {
			pre = existing[a.Spec.ID]
		}
		if pre {
			o.Baits = append(o.Baits, a.Spec.ID)
		}
		note := Fainter.Render(Truncate(a.Spec.Description, noteW))
		if a.Spec.Caveat != "" {
			note = Warn.Render("opt-in") + Fainter.Render(" · "+Truncate(a.Spec.Caveat, noteW-9))
		}
		opts = append(opts, huh.NewOption(fmt.Sprintf("%-*s  %s", nameW, a.Spec.Name, note), a.Spec.ID).Selected(pre))
	}
	baitsDesc := "Every one is fake and harmless. The recommended ones are already ticked."
	if len(skipped) > 0 {
		baitsDesc += "\n" + Fainter.Render("Left out so fake data never gets in the way of your real apps: "+strings.Join(skipped, ", ")+".")
	}

	// ---- response ----
	var presetOpts []huh.Option[string]
	optW := 0
	for _, p := range config.Presets {
		optW = max(optW, len(p.Name))
	}
	for _, p := range config.Presets {
		presetOpts = append(presetOpts, huh.NewOption(fmt.Sprintf("%-*s  ", optW, p.Name)+Fainter.Render(presetShort(p.ID)), p.ID))
	}
	presetOpts = append(presetOpts, huh.NewOption(fmt.Sprintf("%-*s  ", optW, "Custom")+Fainter.Render(presetShort("custom")), "custom"))
	var warnActs, critActs []string
	if ex != nil && ex.Preset == "custom" {
		for _, a := range ex.Responses[config.TierWarn] {
			warnActs = append(warnActs, string(a))
		}
		for _, a := range ex.Responses[config.TierCritical] {
			critActs = append(critActs, string(a))
		}
	} else {
		critActs = []string{string(config.ActionFreeze), string(config.ActionBlockProgram)}
	}
	actionOpts := func() []huh.Option[string] {
		var out []huh.Option[string]
		for _, a := range config.AllActions {
			out = append(out, huh.NewOption(a.Describe(), string(a)))
		}
		return out
	}

	learning := strconv.Itoa(o.LearningDays)
	learnOpts := []huh.Option[string]{
		huh.NewOption("3 days "+Fainter.Render("recommended"), "3"),
		huh.NewOption("7 days", "7"),
		huh.NewOption("No, respond fully right away", "0"),
	}
	if ex != nil {
		learnOpts = append([]huh.Option[string]{huh.NewOption("Keep the current setting", "keep")}, learnOpts...)
		learning = "keep"
	}

	// ---- phone ----
	p := sec.Phone
	phoneKind := p.Kind
	ntfyServer, ntfyTopic, ntfyToken := p.Ntfy.Server, p.Ntfy.Topic, p.Ntfy.Token
	if ntfyServer == "" {
		ntfyServer = "https://ntfy.sh"
	}
	if ntfyTopic == "" {
		ntfyTopic = "sentient1-" + strings.ToLower(randomWord())
	}
	poApp, poUser := p.Pushover.AppToken, p.Pushover.UserKey
	webhook := p.Discord.WebhookURL
	em := p.Email
	emPort := "587"
	if em.Port != 0 {
		emPort = strconv.Itoa(em.Port)
	}
	minTier := string(o.PhoneMinTier)

	// ---- extras ----
	canaryOn := sec.Canary.Email != ""
	canaryEmail := sec.Canary.Email
	cleanRecent := o.CleanRecent
	// This independent build uses manual releases; there is no update channel.
	autoUpdate := false
	confirm := true

	custom := func() bool { return mode == modeCustom }
	notEmpty := func(s string) error {
		if strings.TrimSpace(s) == "" {
			return errors.New("required")
		}
		return nil
	}

	// ---- the intro ----
	var intro *huh.Note
	var modeSel *huh.Select[string]
	if ex == nil {
		intro = huh.NewNote().Title("Let's set up your tripwires").Description(noteText(
			"SENTIENT1 plants fake passwords, wallets and app data around your PC. Nothing legitimate ever reads them, so when something does, SENTIENT1 freezes it, cuts its internet and tells you, before your real data leaves.\n\n" +
				Dim.Render("Protecting ") + Plain.Render(in.User.Name) + Dim.Render("  ·  "+in.User.Profile)))
		modeSel = huh.NewSelect[string]().Title("How would you like to set it up?").Options(
			huh.NewOption("Recommended  "+Fainter.Render(fmt.Sprintf("%d baits · Balanced response · a few quick questions", len(o.Baits))), modeRecommended),
			huh.NewOption("Customize    "+Fainter.Render("pick baits, response, phone alerts and extras"), modeCustom),
		).Value(&mode)
	} else {
		intro = huh.NewNote().Title("Change your setup").Description(noteText(
			"sentient1 is already installed for " + Plain.Render(in.User.Name) + ".\n" +
				Dim.Render("Your alerts, trusted programs and planted baits are kept either way.")))
		modeSel = huh.NewSelect[string]().Title("What would you like to do?").Options(
			huh.NewOption("Keep my settings  "+Fainter.Render("repair or upgrade the install, change nothing"), modeKeep),
			huh.NewOption("Change settings   "+Fainter.Render("baits, response, phone alerts, extras"), modeCustom),
		).Value(&mode)
	}

	form := huh.NewForm(
		huh.NewGroup(intro, modeSel),

		huh.NewGroup(
			huh.NewMultiSelect[string]().Title("Which baits should SENTIENT1 plant?").Description(baitsDesc).
				Options(opts...).Height(min(len(opts)+2, 14)).Value(&o.Baits).
				Validate(func(v []string) error {
					if len(v) == 0 {
						return errors.New("pick at least one bait")
					}
					return nil
				}),
		).WithHideFunc(func() bool { return !custom() }),

		huh.NewGroup(
			huh.NewSelect[string]().Title("What should happen when something takes the bait?").
				DescriptionFunc(func() string { return presetDetail(o.Preset) }, &o.Preset).
				Options(presetOpts...).Value(&o.Preset),
		).WithHideFunc(func() bool { return !custom() }),

		huh.NewGroup(
			huh.NewMultiSelect[string]().Title("For SUSPICIOUS readers").Description("Signed apps in user folders, scripting runtimes, Windows programs.").Options(actionOpts()...).Value(&warnActs),
			huh.NewMultiSelect[string]().Title("For CRITICAL readers").Description("Unsigned programs in Temp/AppData/Downloads, script hosts, anything that sweeps several apps' data.").Options(actionOpts()...).Value(&critActs),
		).WithHideFunc(func() bool { return !custom() || o.Preset != "custom" }),

		huh.NewGroup(
			huh.NewSelect[string]().Title("Start in learning mode?").
				Description("Critical threats are stopped either way. Learning mode only holds back the response to merely suspicious programs for a few days, so your own apps just raise an alert you can answer with one click: \"It's mine\".").
				Options(learnOpts...).Value(&learning),
		).WithHideFunc(func() bool { return !custom() || !warnResponds(o.Preset, warnActs) }),

		huh.NewGroup(
			huh.NewSelect[string]().Title("Get alerts on your phone too?").
				Description("They reach you when you're away, and still get out while the PC is isolated.").
				Options(
					huh.NewOption("Not now", ""),
					huh.NewOption("ntfy      "+Fainter.Render("free app, no account: the easiest"), "ntfy"),
					huh.NewOption("Discord   "+Fainter.Render("a webhook into your server"), "discord"),
					huh.NewOption("Pushover  "+Fainter.Render("if you already use it"), "pushover"),
					huh.NewOption("Email     "+Fainter.Render("through your mail provider's SMTP"), "email"),
				).Value(&phoneKind),
		).WithHideFunc(func() bool { return mode == modeKeep }),

		huh.NewGroup(
			huh.NewNote().Title("Phone alerts with ntfy").Description(noteText(
				Good.Render("1")+"  Install the free "+Plain.Render("ntfy")+" app from the App Store or Google Play.\n"+
					Good.Render("2")+"  Tap "+Plain.Render("+")+" and subscribe to the topic below.\n"+
					Good.Render("3")+"  That's it. Setup ends by sending a test, so you'll know it works.")),
			huh.NewInput().Title("Topic").Description("Anyone who knows it can read your alerts, so keep it hard to guess.").Value(&ntfyTopic).Validate(notEmpty),
			huh.NewInput().Title("Server").Value(&ntfyServer).Validate(validURL),
			huh.NewInput().Title("Access token").Description("Only for protected topics on your own server.").EchoMode(huh.EchoModePassword).Value(&ntfyToken),
		).WithHideFunc(func() bool { return mode == modeKeep || phoneKind != "ntfy" }),
		huh.NewGroup(
			huh.NewInput().Title("Discord webhook URL").Description("Server Settings › Integrations › Webhooks › New Webhook › Copy Webhook URL").EchoMode(huh.EchoModePassword).Value(&webhook).Validate(validURL),
		).WithHideFunc(func() bool { return mode == modeKeep || phoneKind != "discord" }),
		huh.NewGroup(
			huh.NewInput().Title("Pushover application token").EchoMode(huh.EchoModePassword).Value(&poApp).Validate(notEmpty),
			huh.NewInput().Title("Pushover user key").EchoMode(huh.EchoModePassword).Value(&poUser).Validate(notEmpty),
		).WithHideFunc(func() bool { return mode == modeKeep || phoneKind != "pushover" }),
		huh.NewGroup(
			huh.NewInput().Title("SMTP server").Placeholder("smtp.gmail.com").Value(&em.Host).Validate(notEmpty),
			huh.NewInput().Title("Port").Description("587 = STARTTLS, 465 = TLS").Value(&emPort).Validate(func(s string) error {
				if _, err := strconv.Atoi(s); err != nil {
					return errors.New("a number")
				}
				return nil
			}),
			huh.NewInput().Title("Username").Value(&em.Username),
			huh.NewInput().Title("Password").Description("For Gmail and Outlook, an app password.").EchoMode(huh.EchoModePassword).Value(&em.Password),
			huh.NewInput().Title("Send alerts to").Value(&em.To).Validate(validEmail),
		).WithHideFunc(func() bool { return mode == modeKeep || phoneKind != "email" }),
		huh.NewGroup(
			huh.NewSelect[string]().Title("Which alerts should reach your phone?").Options(
				huh.NewOption("Suspicious and critical "+Fainter.Render("recommended"), string(config.TierWarn)),
				huh.NewOption("Critical only", string(config.TierCritical)),
				huh.NewOption("Everything", string(config.TierInfo)),
			).Value(&minTier),
		).WithHideFunc(func() bool { return !custom() || phoneKind == "" }),

		huh.NewGroup(
			huh.NewConfirm().Title("Add canary tokens?").
				Description("SENTIENT1 hides fake AWS keys and a tracking link inside your baits, made with the free canarytokens.org service. If a stealer gets away with your files and USES them later, you get an email, even if this PC never got the chance to warn you.\n"+
					Fainter.Render("Your email address is shared with canarytokens.org.")).
				Affirmative("Yes").Negative("No").Value(&canaryOn),
		).WithHideFunc(func() bool { return !custom() }),
		huh.NewGroup(
			huh.NewInput().Title("Email for canary alerts").Value(&canaryEmail).Validate(validEmail),
		).WithHideFunc(func() bool { return !custom() || !canaryOn }),
		huh.NewGroup(
			huh.NewConfirm().Title("Keep baits out of your Recent files?").
				Description("If you open a bait yourself, Windows lists it under Recent files, and apps like Copilot then read it. SENTIENT1 removes those shortcuts automatically.").
				Affirmative("Yes").Negative("No").Value(&cleanRecent),
		).WithHideFunc(func() bool { return !custom() }),

		huh.NewGroup(
			huh.NewConfirm().Title("Keep sentient1 up to date automatically?").
				Description("Once a day it checks GitHub and installs a new version, but only if the release is signed with SENTIENT1's release key and the download matches its signed checksum.").
				Affirmative("Yes, automatically").Negative("No, I'll update myself").Value(&autoUpdate),
		).WithHideFunc(func() bool { return true }),

		huh.NewGroup(
			huh.NewNote().Title("Ready").DescriptionFunc(func() string {
				return noteText(reviewSummary(mode, len(o.Baits)+len(o.CustomBaits), o.Preset, phoneKind, ntfyTopic, canaryOn && custom() || (mode == modeKeep && canaryEmail != ""), autoUpdate, learning, warnResponds(o.Preset, warnActs)))
			}, []any{&mode, &o.Baits, &o.Preset, &phoneKind, &ntfyTopic, &canaryOn, &autoUpdate, &learning, &warnActs}),
			huh.NewConfirm().Title(map[bool]string{true: "Go ahead?", false: "Install sentient1?"}[ex != nil]).
				Affirmative(map[bool]string{true: "Apply", false: "Install"}[ex != nil]).Negative("Cancel").Value(&confirm),
		),
	).WithTheme(Theme()).WithKeyMap(KeyMap()).WithShowHelp(true).WithWidth(formW)

	finish := func() (install.Options, bool) {
		if !confirm {
			return o, false
		}
		if mode == modeKeep && ex != nil {
			// Same settings as now; only the install itself is redone.
			if ex.Preset == "custom" {
				o.Responses = ex.Responses
			}
			o.Phone = sec.Phone
			o.CanaryEmail = sec.Canary.Email
			o.AutoUpdate = autoUpdate
			return o, true
		}
		if o.Preset == "custom" {
			o.Responses = map[config.Tier][]config.Action{}
			for _, a := range warnActs {
				o.Responses[config.TierWarn] = append(o.Responses[config.TierWarn], config.Action(a))
			}
			for _, a := range critActs {
				o.Responses[config.TierCritical] = append(o.Responses[config.TierCritical], config.Action(a))
			}
		}
		if mode == modeRecommended || !warnResponds(o.Preset, warnActs) {
			if learning != "keep" {
				learning = "0" // nothing for learning mode to hold back with this response
			}
		}
		if learning == "keep" {
			o.KeepLearning = true
		} else {
			o.KeepLearning = false
			o.LearningDays, _ = strconv.Atoi(learning)
		}
		o.PhoneMinTier = config.Tier(minTier)
		o.CleanRecent = cleanRecent
		o.AutoUpdate = autoUpdate
		o.Phone = config.PhoneConfig{Kind: phoneKind}
		switch phoneKind {
		case "ntfy":
			o.Phone.Ntfy = config.NtfyConfig{Server: strings.TrimSpace(ntfyServer), Topic: strings.TrimSpace(ntfyTopic), Token: ntfyToken}
		case "discord":
			o.Phone.Discord = config.DiscordConfig{WebhookURL: strings.TrimSpace(webhook)}
		case "pushover":
			o.Phone.Pushover = config.PushoverConfig{AppToken: strings.TrimSpace(poApp), UserKey: strings.TrimSpace(poUser)}
		case "email":
			em.Port, _ = strconv.Atoi(emPort)
			em.ImplicitTLS = em.Port == 465
			em.Host, em.To = strings.TrimSpace(em.Host), strings.TrimSpace(em.To)
			o.Phone.Email = em
		}
		if canaryOn && custom() {
			o.CanaryEmail = strings.TrimSpace(canaryEmail)
		} else if mode == modeRecommended {
			o.CanaryEmail = ""
		}
		return o, true
	}
	setMode := func(m, phone string) { mode, phoneKind = m, phone }
	return &wizard{form: form, finish: finish, setMode: setMode}
}

// presetDetail explains a response preset in plain words.
func presetDetail(id string) string {
	switch id {
	case "alert":
		return "Tell you, and nothing else. SENTIENT1 never touches a process or the network."
	case "balanced":
		return "A critical reader (an unsigned program from Temp or Downloads, a script host, anything going through several apps' data) is frozen and cut off from the internet; the rest of your PC stays online. Merely suspicious readers just alert you."
	case "strict":
		return "Critical readers are frozen and the whole PC is cut off from the network until you say so. Suspicious readers are frozen too: expect to confirm a few of your own apps at first."
	case "custom":
		return "Choose what happens for suspicious and for critical readers yourself."
	}
	return ""
}

// reviewSummary is the last screen before installing: what's about to happen.
func reviewSummary(mode string, nBaits int, preset, phone, topic string, canary, autoUpdate bool, learning string, learningMatters bool) string {
	if mode == modeKeep {
		return "SENTIENT1 will be reinstalled in place with your current settings:\n" +
			Fainter.Render("program files, the background service, Windows auditing and your baits are checked and repaired.")
	}
	name := map[string]string{"alert": "Alert only", "balanced": "Balanced", "strict": "Strict", "custom": "Custom"}[preset]
	rows := [][2]string{
		{"Baits", fmt.Sprintf("%d fake files and app profiles", nBaits)},
		{"Response", name + Fainter.Render("  ·  "+presetShort(preset))},
	}
	if learningMatters && learning != "0" && learning != "keep" && mode == modeCustom {
		rows = append(rows, [2]string{"Learning", learning + " days" + Fainter.Render("  ·  critical threats are stopped from the start")})
	}
	switch phone {
	case "":
		rows = append(rows, [2]string{"Phone", Fainter.Render("off  ·  turn on later with ") + Code.Render("sentient1 configure")})
	case "ntfy":
		rows = append(rows, [2]string{"Phone", "ntfy, topic " + topic + Fainter.Render("  ·  a test is sent at the end")})
	default:
		rows = append(rows, [2]string{"Phone", strings.ToUpper(phone[:1]) + phone[1:] + Fainter.Render("  ·  a test is sent at the end")})
	}
	if canary {
		rows = append(rows, [2]string{"Canary", "on"})
	}
	if autoUpdate {
		rows = append(rows, [2]string{"Updates", "automatic" + Fainter.Render("  ·  signed releases only")})
	} else {
		rows = append(rows, [2]string{"Updates", "manual" + Fainter.Render("  ·  ") + Code.Render("sentient1 update")})
	}
	rows = append(rows, [2]string{"Installs to", paths.InstallDir()})
	return KV(rows)
}

func presetShort(id string) string {
	switch id {
	case "alert":
		return "alerts only, never acts"
	case "balanced":
		return "critical readers frozen and cut off"
	case "strict":
		return "critical: PC isolated · suspicious: frozen"
	}
	return "your own choice of actions"
}

// noteText escapes text for a huh Note, which treats \ _ * and ` as markup
// (Windows paths and user names are full of them).
func noteText(s string) string {
	return strings.NewReplacer(`\`, `\\`, "_", `\_`, "*", `\*`, "`", "\\`").Replace(s)
}

// KeyMap is huh's default without type-to-filter (the lists are short, and
// the "/ filter" hint is just noise).
func KeyMap() *huh.KeyMap {
	k := huh.NewDefaultKeyMap()
	k.Select.Filter.SetEnabled(false)
	k.MultiSelect.Filter.SetEnabled(false)
	return k
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// warnResponds reports whether suspicious (warn) readers get any response
// beyond an alert; only then does learning mode change anything.
func warnResponds(preset string, customWarn []string) bool {
	if preset == "custom" {
		return len(customWarn) > 0
	}
	p, ok := config.PresetByID(preset)
	return ok && len(p.Responses[config.TierWarn]) > 0
}

func validURL(s string) error {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("enter a full URL starting with https://")
	}
	return nil
}

func validEmail(s string) error {
	if _, err := mail.ParseAddress(strings.TrimSpace(s)); err != nil {
		return errors.New("enter a valid email address")
	}
	return nil
}

func randomWord() string {
	const letters = "abcdefghijkmnpqrstuvwxyz23456789"
	b := make([]byte, 10)
	for i := range b {
		b[i] = letters[int(randByte())%len(letters)]
	}
	return string(b)
}
