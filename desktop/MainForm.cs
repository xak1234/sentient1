using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Sentient1;

internal sealed class MainForm : Form
{
    private static string DesktopVersion => typeof(MainForm).Assembly.GetName().Version?.ToString(3) ?? "dev";
    private readonly System.Windows.Forms.Timer timer = new() { Interval = 5000 };
    private readonly Label stateLabel = Theme.Label("Connecting to monitor…", 14, Theme.Green, true);
    private readonly Label footer = Theme.Label("Reading local status", 9, Theme.Muted);
    private readonly Label pageTitle = Theme.Label("Overview", 23, Theme.Text, true);
    private readonly Label pageDescription = Theme.Label("Live protection, coverage and recent evidence.", 10, Theme.Muted);
    private readonly Label terminalState = Theme.Label("LOCAL SESSION", 9, Theme.Green, true);
    private readonly Panel pageHost = new() { Dock = DockStyle.Fill };
    private readonly Dictionary<string, Control> pages = [];
    private readonly Dictionary<string, Button> navigation = [];
    private readonly Dictionary<string, Label> metrics = [];
    private readonly RichTextBox terminal = new WheelTerminal()
    {
        Dock = DockStyle.Fill,
        BackColor = Color.FromArgb(5, 11, 8),
        ForeColor = Theme.Green,
        BorderStyle = BorderStyle.None,
        ReadOnly = true,
        DetectUrls = false,
        Font = new Font("Consolas", 9.5F),
        WordWrap = true,
        ScrollBars = RichTextBoxScrollBars.None
    };
    private readonly TextBox overview = Theme.ReadOnlyText();
    private readonly TextBox evidence = Theme.ReadOnlyText(true);
    private readonly TextBox filter = Theme.TextBox("Filter by reader, path or alert ID");
    private readonly ComboBox severity = Theme.Combo("All severities", "critical", "warn", "info");
    private readonly DataGridView detections = Theme.Grid("Time", "Severity", "Reader / event", "Status", "Evidence");
    private readonly DataGridView decoys = Theme.Grid("Decoy", "Kind", "Status", "Location");
    private readonly DataGridView health = Theme.Grid("Check", "Result", "Evidence");
    private readonly List<JsonElement> alerts = [];
    private readonly SetupView setup;
    private readonly Panel confirmPanel = new() { Dock = DockStyle.Fill, BackColor = Theme.Raised, Padding = new Padding(12), Visible = false };
    private readonly Label confirmText = Theme.Label("", 10, Theme.Amber);
    private readonly TableLayoutPanel mainLayout;
    private readonly NotifyIcon tray = new();
    private readonly Icon appIcon;
    private readonly ActivitySignal activity = new();
    private readonly List<Button> actionButtons = [];
    private Button? freezeButton;
    private Func<Task>? pendingAction;
    private bool refreshing;
    private bool acting;
    private bool loadedOnce;
    private bool closing;
    private string lastState = "";
    private string lastError = "";

    internal MainForm(bool uiTest = false)
    {
        Text = "sentient1 · Protection console";
        appIcon = Icon.ExtractAssociatedIcon(Environment.ProcessPath!) ?? (Icon)SystemIcons.Shield.Clone();
        Icon = appIcon; ShowInTaskbar = true; MinimizeBox = true; MaximizeBox = true;
        BackColor = Theme.Background; ForeColor = Theme.Text; Font = new Font("Segoe UI", 10);
        MinimumSize = new Size(1080, 780); Size = new Size(1320, 950); StartPosition = FormStartPosition.CenterScreen;
        DoubleBuffered = true;
        mainLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, Padding = new Padding(22, 14, 22, 5) };
        mainLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 84));
        mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 0));
        mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 184));
        mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));
        var header = new TechHeader { Dock = DockStyle.Fill, Margin = new Padding(0, 0, 0, 10) };
        var brand = Theme.Label("sentient1", 30, Theme.Green, true); brand.Location = new Point(0, 0); header.Controls.Add(brand);
        var strap = Theme.Label("DECOY DEFENCE  /  PROTECTION CONSOLE", 8.5F, Theme.Muted); strap.Location = new Point(4, 53); header.Controls.Add(strap);
        stateLabel.AutoSize = false; stateLabel.Size = new Size(480, 56); stateLabel.TextAlign = ContentAlignment.MiddleRight;
        stateLabel.Anchor = AnchorStyles.Right | AnchorStyles.Top; header.Controls.Add(stateLabel);
        header.Controls.Add(activity);
        header.Resize += (_, _) =>
        {
            stateLabel.Location = new Point(Math.Max(320, header.Width - stateLabel.Width), 5);
            activity.Location = new Point(Math.Clamp((header.Width - activity.Width) / 2, 260, Math.Max(260, header.Width - 760)), 1);
        };
        mainLayout.Controls.Add(header, 0, 0);
        var body = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
        body.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 182)); body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        var sidebar = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 3, ColumnCount = 1, Padding = new Padding(0, 16, 16, 0) };
        sidebar.RowStyles.Add(new RowStyle(SizeType.AutoSize)); sidebar.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); sidebar.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var nav = Theme.Flow(true); nav.Controls.Add(Theme.Label("WORKSPACE", 8, Theme.Muted, true));
        foreach (var title in new[] { "Overview", "Detections", "Decoys", "Health", "Setup" })
        {
            var button = Theme.Button(title); button.Width = 158; button.Height = 43; button.TextAlign = ContentAlignment.MiddleLeft;
            button.Click += async (_, _) => await Guard(() => Navigate(title)); nav.Controls.Add(button); navigation[title] = button;
        }
        sidebar.Controls.Add(nav, 0, 0);
        var sidebarFoot = Theme.Flow(true);
        sidebarFoot.Controls.Add(Theme.Label("AUDIT ENGINE", 8, Theme.Green, true));
        sidebarFoot.Controls.Add(Theme.Label("Local evidence\nBackground monitoring\nManual updates", 9, Theme.Muted));
        sidebarFoot.Controls.Add(Theme.Label($"sentient1  /  {DesktopVersion}", 8, Theme.Muted)); sidebar.Controls.Add(sidebarFoot, 0, 2);
        body.Controls.Add(sidebar, 0, 0);
        var content = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Padding = new Padding(12, 8, 0, 12) };
        content.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        content.RowStyles.Add(new RowStyle(SizeType.Absolute, 80)); content.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var heading = Theme.Flow(true); heading.Controls.Add(pageTitle); heading.Controls.Add(pageDescription); content.Controls.Add(heading, 0, 0);
        content.Controls.Add(pageHost, 0, 1); body.Controls.Add(content, 1, 0); mainLayout.Controls.Add(body, 0, 1);
        setup = new SetupView(Log, Ask, RunOperation);
        pages["Overview"] = BuildOverview(); pages["Detections"] = BuildDetections(); pages["Decoys"] = decoys; pages["Health"] = BuildHealth(); pages["Setup"] = setup;
        foreach (var page in pages.Values) { page.Dock = DockStyle.Fill; page.Visible = false; pageHost.Controls.Add(page); }
        BuildConfirmation(); mainLayout.Controls.Add(confirmPanel, 0, 2);
        var terminalPanel = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = Theme.Surface, Padding = new Padding(12, 9, 12, 10), ColumnCount = 1, RowCount = 2, Margin = new Padding(0, 8, 0, 4) };
        terminalPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 30)); terminalPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var terminalTop = new Panel { Dock = DockStyle.Fill };
        terminalState.Location = new Point(0, 1); terminalTop.Controls.Add(terminalState);
        var clear = Theme.Button("Clear"); clear.MinimumSize = new Size(65, 22); clear.AutoSize = false; clear.Size = new Size(70, 24); clear.Padding = Padding.Empty;
        clear.Anchor = AnchorStyles.Top | AnchorStyles.Right; terminalTop.Controls.Add(clear);
        terminalTop.Resize += (_, _) => clear.Location = new Point(terminalTop.Width - 74, 0); clear.Click += (_, _) => terminal.Clear();
        terminalPanel.Controls.Add(terminalTop, 0, 0); terminalPanel.Controls.Add(terminal, 0, 1); mainLayout.Controls.Add(terminalPanel, 0, 3);
        footer.Dock = DockStyle.Fill; footer.TextAlign = ContentAlignment.MiddleLeft; mainLayout.Controls.Add(footer, 0, 4); Controls.Add(mainLayout);
        tray.Icon = appIcon; tray.Text = "sentient1 · Open protection console";
        var trayMenu = new ContextMenuStrip { BackColor = Theme.Surface, ForeColor = Theme.Text };
        trayMenu.Items.Add("Open sentient1", null, (_, _) => RestoreWindow());
        trayMenu.Items.Add("Exit dashboard", null, (_, _) => Close()); tray.ContextMenuStrip = trayMenu;
        tray.DoubleClick += (_, _) => RestoreWindow();
        Resize += (_, _) => { if (!closing) tray.Visible = WindowState == FormWindowState.Minimized; };
        filter.TextChanged += (_, _) => PopulateAlerts(); severity.SelectedIndexChanged += (_, _) => PopulateAlerts();
        detections.SelectionChanged += (_, _) => ShowEvidence();
        timer.Tick += async (_, _) => await RefreshSnapshot();
        Shown += async (_, _) =>
        {
            await Navigate("Overview"); Log($"sentient1 {DesktopVersion} · local protection console ready.");
            await RefreshSnapshot(); timer.Start();
            if (uiTest) await RunUiTest();
        };
        FormClosing += (_, e) =>
        {
            if (acting && e.CloseReason == CloseReason.UserClosing) { e.Cancel = true; Log("Wait for the current operation to finish before closing."); return; }
            closing = true; timer.Stop(); tray.Visible = false;
        };
    }

    private Control BuildOverview()
    {
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Margin = Padding.Empty };
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 100)); layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var cards = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 1, Margin = new Padding(0, 0, 0, 12) };
        foreach (var key in new[] { "SERVICE", "DECOY COVERAGE", "ACTIVE RESPONSES", "RESPONSE POLICY" })
        {
            cards.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
            var card = Theme.Flow(true); card.Dock = DockStyle.Fill; card.BackColor = Theme.Surface; card.Padding = new Padding(14, 10, 5, 8); card.Margin = new Padding(0, 0, 10, 0);
            card.Controls.Add(Theme.Label(key, 8, Theme.Muted, true)); var value = Theme.Label("—", 18, Theme.Green, true); metrics[key] = value; card.Controls.Add(value); cards.Controls.Add(card);
        }
        layout.Controls.Add(cards, 0, 0);
        var actions = Theme.Flow();
        AddButton(actions, "Open setup", () => Navigate("Setup"), true);
        AddButton(actions, "Safe reader test", () => { Ask("Run a harmless decoy reader test? It also sends test alerts through any configured notification provider.", () => RunOperation(new EngineRequest("test"))); return Task.CompletedTask; });
        AddButton(actions, "Export report", ExportReport); AddButton(actions, "Refresh", RefreshSnapshot); layout.Controls.Add(actions, 0, 1);
        var panel = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Surface, Padding = new Padding(18), Margin = new Padding(0, 8, 0, 0) }; panel.Controls.Add(overview); layout.Controls.Add(panel, 0, 2); return layout;
    }

    private Control BuildDetections()
    {
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        detections.Columns[2].FillWeight = 240;
        detections.Columns[2].DefaultCellStyle.WrapMode = DataGridViewTriState.True;
        detections.AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.AllCells;
        var filters = Theme.Flow(); severity.Width = 160; filters.Controls.Add(filter); filters.Controls.Add(severity); layout.Controls.Add(filters, 0, 0);
        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterWidth = 6, BackColor = Theme.Border };
        split.Panel1.Controls.Add(detections); split.Panel2.Padding = new Padding(10); split.Panel2.BackColor = Theme.Surface; split.Panel2.Controls.Add(evidence); layout.Controls.Add(split, 0, 1);
        var actions = Theme.Flow(); actions.Padding = new Padding(0, 10, 0, 0);
        freezeButton = AddButton(actions, "Freeze once", () => IncidentAction("freeze", "Pause this reader until you choose Resume once? All components in this process will pause. Other processes and the automatic response policy are unchanged."));
        freezeButton.Enabled = false;
        AddButton(actions, "Resume once", () => IncidentAction("resume", "Resume this reader and restore its program access? It will not be permanently trusted."));
        AddButton(actions, "Trust reader", () => IncidentAction("trust", "Trust and resume this reader? Only continue after verifying its evidence and publisher."));
        AddButton(actions, "Kill frozen", () => IncidentAction("kill", "Terminate this alert's frozen processes? Their unsaved work will be lost."));
        AddButton(actions, "Release all", () => { Ask("Resume all frozen processes and remove sentient1 network restrictions? Suspicious programs may continue running.", () => RunOperation(new EngineRequest("release"))); return Task.CompletedTask; });
        layout.Controls.Add(actions, 0, 2); return layout;
    }

    private Control BuildHealth()
    {
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var actions = Theme.Flow();
        AddButton(actions, "Run diagnostics", () => RunOperation(new EngineRequest("doctor")), true);
        AddButton(actions, "Repair monitor", () => { Ask("Repair monitor configuration, audit rules and selected decoys?", () => RunOperation(new EngineRequest("repair"))); return Task.CompletedTask; });
        AddButton(actions, "Uninstall monitor", () => { Ask("Remove the background monitor and its decoys, and release containment? Alert history will be kept.", () => RunOperation(new EngineRequest("uninstall"))); return Task.CompletedTask; });
        layout.Controls.Add(actions, 0, 0); layout.Controls.Add(health, 0, 1); return layout;
    }

    private void BuildConfirmation()
    {
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1 };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        confirmText.AutoSize = false; confirmText.Dock = DockStyle.Fill; layout.Controls.Add(confirmText, 0, 0);
        var actions = Theme.Flow(); actions.Dock = DockStyle.Fill;
        var cancel = Theme.Button("Cancel"); var apply = Theme.Button("Confirm", true);
        cancel.Click += (_, _) => ClearConfirmation();
        apply.Click += async (_, _) => { var action = pendingAction; ClearConfirmation(); if (action is not null) await Guard(action); };
        actions.Controls.Add(cancel); actions.Controls.Add(apply); layout.Controls.Add(actions, 1, 0); confirmPanel.Controls.Add(layout);
    }
    private void Ask(string message, Func<Task> action)
    {
        if (acting) return;
        pendingAction = action; confirmText.Text = message; mainLayout.RowStyles[2].Height = 128; confirmPanel.Visible = true;
    }
    private void ClearConfirmation() { pendingAction = null; confirmPanel.Visible = false; mainLayout.RowStyles[2].Height = 0; }
    private Button AddButton(FlowLayoutPanel panel, string text, Func<Task> action, bool primary = false)
    {
        var button = Theme.Button(text, primary); actionButtons.Add(button);
        button.Click += async (_, _) => { if (!acting) await Guard(action); }; panel.Controls.Add(button);
        return button;
    }
    private async Task Guard(Func<Task> action)
    {
        try { await action(); }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) { Log("Administrator request cancelled. No operation was started."); }
        catch (Exception ex) { Log("ERROR  " + ex.Message); }
    }
    private async Task Navigate(string name)
    {
        if (acting) return;
        ClearConfirmation();
        foreach (var pair in pages) pair.Value.Visible = pair.Key == name;
        foreach (var pair in navigation) { pair.Value.BackColor = pair.Key == name ? Theme.Raised : Theme.Background; pair.Value.ForeColor = pair.Key == name ? Theme.Green : Theme.Muted; }
        pageTitle.Text = name;
        pageDescription.Text = name switch
        {
            "Detections" => "Filter detections, inspect evidence and manage containment.",
            "Decoys" => "Live decoy health and protected locations.",
            "Health" => "Audit readiness, monitor diagnostics and recovery.",
            "Setup" => "Review your settings and apply them from this window.",
            _ => "Live protection, coverage and recent evidence."
        };
        if (name == "Setup") { if (!setup.Loaded) await setup.LoadAsync(); setup.Focus(); }
    }

    private async Task RunOperation(EngineRequest request)
    {
        if (acting) return;
        acting = true; timer.Stop(); setup.Enabled = false;
        activity.UpdateStatus(false, false, default);
        foreach (var button in actionButtons) button.Enabled = false;
        foreach (var button in navigation.Values) button.Enabled = false;
        terminalState.Text = "RUNNING  /  " + request.Operation.ToUpperInvariant();
        Log("> " + request.Operation + " · waiting for the Windows administrator helper…");
        try { await Engine.RunAsync(request, Log); Log("OK  " + request.Operation + " completed."); }
        finally
        {
            acting = false;
            if (!IsDisposed)
            {
                foreach (var button in actionButtons) button.Enabled = true;
                if (freezeButton is not null) freezeButton.Enabled = false;
                foreach (var button in navigation.Values) button.Enabled = true;
                setup.Enabled = true; terminalState.Text = "LOCAL SESSION";
                await RefreshSnapshot(); timer.Start();
            }
        }
    }
    private Task IncidentAction(string operation, string question)
    {
        if (detections.CurrentRow?.Tag is not string id) { Log("Select a detection first."); return Task.CompletedTask; }
        var selected = alerts.FirstOrDefault(x => S(x, "id") == id);
        if (operation == "trust" && selected.ValueKind == JsonValueKind.Object &&
            selected.TryGetProperty("process", out var process) && process.ValueKind == JsonValueKind.Object &&
            process.TryGetProperty("hosted", out var hosted) && hosted.ValueKind == JsonValueKind.Object)
            question = "Approve this incident and resume the reader? Shared hosts are approved once; no permanent trust rule will be added.";
        Ask(question, () => RunOperation(new EngineRequest(operation, id))); return Task.CompletedTask;
    }
    private void RestoreWindow() { Show(); WindowState = FormWindowState.Normal; Activate(); tray.Visible = false; }
    private void Log(string text)
    {
        if (IsDisposed || closing) return;
        if (InvokeRequired) { BeginInvoke(() => Log(text)); return; }
        if (terminal.TextLength > 150000) { terminal.Select(0, 50000); terminal.SelectedText = ""; }
        terminal.SelectionStart = terminal.TextLength; terminal.SelectionLength = 0;
        terminal.SelectionColor = text.Contains("ERROR", StringComparison.OrdinalIgnoreCase) ? Theme.Red : text.Contains("WARN", StringComparison.OrdinalIgnoreCase) ? Theme.Amber : Theme.Green;
        terminal.AppendText($"[{DateTime.Now:HH:mm:ss}] {text.TrimEnd()}\n"); terminal.ScrollToCaret();
    }

    private async Task RefreshSnapshot()
    {
        if (refreshing || acting || IsDisposed || closing) return;
        refreshing = true;
        try
        {
            using var document = JsonDocument.Parse(await Engine.CaptureAsync("status", "--json"));
            if (IsDisposed || closing) return;
            var data = document.RootElement; var assessment = data.GetProperty("assessment");
            _ = DateTimeOffset.TryParse(S(data, "heartbeat"), out var heartbeat);
            activity.UpdateStatus(S(data, "service") == "running", S(assessment, "level") == "healthy", heartbeat);
            var state = S(assessment, "title"); stateLabel.Text = "●  " + state;
            stateLabel.ForeColor = S(assessment, "level") switch { "healthy" => Theme.Green, "response" => Theme.Red, _ => Theme.Amber };
            metrics["SERVICE"].Text = S(data, "service"); metrics["DECOY COVERAGE"].Text = $"{N(assessment, "healthy")} / {N(assessment, "total")}";
            metrics["ACTIVE RESPONSES"].Text = N(assessment, "activeResponses").ToString(); metrics["RESPONSE POLICY"].Text = S(data, "policy");
            if (lastState != state) { Log(state + $" · {N(assessment, "healthy")} healthy decoys · {S(data, "policy")} policy."); lastState = state; }
            alerts.Clear(); foreach (var alert in Array(data, "alerts")) alerts.Add(alert.Clone()); PopulateAlerts(true);
            var decoyTop = decoys.FirstDisplayedScrollingRowIndex; var healthTop = health.FirstDisplayedScrollingRowIndex;
            decoys.Rows.Clear(); foreach (var decoy in Array(data, "baits")) decoys.Rows.Add(S(decoy, "name"), S(decoy, "kind"), S(decoy, "status"), string.Join(" | ", Array(decoy, "paths").Select(x => x.GetString())));
            health.Rows.Clear(); foreach (var check in Array(data, "health"))
            {
                var row = health.Rows[health.Rows.Add(S(check, "name"), B(check, "ok") ? "OK" : "ATTENTION", S(check, "detail"))]; row.Cells[1].Style.ForeColor = B(check, "ok") ? Theme.Green : Theme.Amber;
            }
            RestoreScroll(decoys, decoyTop); RestoreScroll(health, healthTop);
            var text = new StringBuilder();
            text.AppendLine("PROTECTION STATUS").AppendLine();
            foreach (var reason in Array(assessment, "reasons")) text.AppendLine("• " + reason.GetString());
            foreach (var problem in Array(data, "problems")) text.AppendLine("• " + problem.GetString());
            if (!B(data, "installed")) text.AppendLine("Open Setup to review decoys and response policy, then install the monitor.");
            text.AppendLine().AppendLine("READER DETECTION").AppendLine(B(data, "instant") ? "Windows audit events plus optional oplock timing inference. Review attribution evidence before acting." : "Windows Security audit events identify programs reading the decoys. Optional oplock timing inference is off.");
            text.AppendLine().AppendLine("RECENT ACTIVITY");
            if (alerts.Count == 0) text.AppendLine("No recent detections recorded. This does not prove the PC is clean.");
            foreach (var alert in alerts.Take(4)) text.AppendLine($"{LocalTime(S(alert, "time"))}  ·  {S(alert, "tier").ToUpperInvariant()}  ·  {S(alert, "title")}");
            text.AppendLine().AppendLine("MONITORING CONTINUES IN THE BACKGROUND").AppendLine("Minimise keeps this dashboard in the taskbar and adds its shield to the notification area. Closing the dashboard leaves the installed monitor service running.");
            text.AppendLine().AppendLine("Decoys are additional tripwires. Malware that avoids them can escape detection, and legitimate backup tools can trigger them. Keep Microsoft Defender enabled.");
            overview.Text = text.ToString(); footer.Text = $"Updated {DateTime.Now:T}  ·  {alerts.Count} recent detections  ·  Refresh 5s  ·  Engine {S(data, "version")}  /  Desktop {DesktopVersion}";
            loadedOnce = true; lastError = "";
        }
        catch (Exception ex)
        {
            if (IsDisposed || closing) return;
            activity.UpdateStatus(false, false, default);
            stateLabel.Text = "●  Status unavailable"; stateLabel.ForeColor = Theme.Amber;
            footer.Text = (loadedOnce ? "Displayed data is stale. " : "") + ex.Message;
            if (freezeButton is not null) freezeButton.Enabled = false;
            if (lastError != ex.Message) { Log("ERROR  " + footer.Text); lastError = ex.Message; }
        }
        finally { refreshing = false; }
    }
    private static void RestoreScroll(DataGridView grid, int first)
    {
        if (first >= 0 && grid.RowCount > 0) grid.FirstDisplayedScrollingRowIndex = Math.Min(first, grid.RowCount - 1);
    }
    private void PopulateAlerts(bool preserveScroll = false)
    {
        var first = detections.FirstDisplayedScrollingRowIndex;
        var selected = detections.CurrentRow?.Tag as string; detections.Rows.Clear();
        foreach (var alert in alerts)
        {
            var tier = S(alert, "tier");
            if (severity.SelectedIndex > 0 && tier != severity.Text) continue;
            if (!string.IsNullOrWhiteSpace(filter.Text) && !alert.GetRawText().Contains(filter.Text, StringComparison.OrdinalIgnoreCase)) continue;
            var reader = alert.TryGetProperty("process", out var process) && process.ValueKind == JsonValueKind.Object ? ReaderName(process) : S(alert, "title");
            var row = detections.Rows[detections.Rows.Add(LocalTime(S(alert, "time")), tier, reader, S(alert, "status"), B(alert, "test") ? "Safe test" : B(alert, "instant") ? "Oplock inference" : "Audit / health event")];
            row.Tag = S(alert, "id"); row.Cells[1].Style.ForeColor = tier switch { "critical" => Theme.Red, "warn" => Theme.Amber, _ => Theme.Green };
            if (S(alert, "id") == selected) detections.CurrentCell = row.Cells[0];
        }
        if (preserveScroll) RestoreScroll(detections, first);
        ShowEvidence();
    }
    private void ShowEvidence()
    {
        if (freezeButton is not null) freezeButton.Enabled = false;
        if (detections.CurrentRow?.Tag is not string id) { evidence.Text = "Select a detection to inspect its recorded evidence."; return; }
        var alert = alerts.FirstOrDefault(x => S(x, "id") == id);
        if (alert.ValueKind == JsonValueKind.Object)
        {
            evidence.Text = FormatEvidence(alert);
            if (freezeButton is not null && alert.TryGetProperty("controls", out var controls))
                freezeButton.Enabled = !acting && B(controls, "canFreeze");
        }
    }

    private static string ReaderName(JsonElement process) => S(process, "displayName") is { Length: > 0 } name ? name : Path.GetFileName(S(process, "image"));

    internal static string FormatEvidence(JsonElement alert)
    {
        var text = new StringBuilder();
        if (alert.TryGetProperty("controls", out var controls))
            text.AppendLine("FREEZE ONCE: " + S(controls, "freezeReason")).AppendLine();
        if (alert.TryGetProperty("process", out var process) && process.ValueKind == JsonValueKind.Object)
        {
            text.AppendLine(ReaderName(process)).AppendLine("Process ID: " + N(process, "pid")).AppendLine("Executable: " + S(process, "image"));
            foreach (var bait in Array(alert, "baits"))
                text.AppendLine().AppendLine("File " + S(bait, "access") + ": " + S(bait, "name")).AppendLine(S(bait, "path"));
            if (process.TryGetProperty("hosted", out var hosted) && hosted.ValueKind == JsonValueKind.Object)
            {
                foreach (var component in Array(hosted, "components"))
                {
                    text.AppendLine().AppendLine("Component: " + S(component, "name"));
                    if (S(component, "module") is { Length: > 0 } module) text.AppendLine("File: " + module);
                    text.AppendLine("Evidence: " + S(component, "source"));
                    if (component.TryGetProperty("signature", out var signature))
                        text.AppendLine("Component signature: " + (B(signature, "valid") ? "Valid — " + S(signature, "signer") : "Not verified as valid"));
                }
                text.AppendLine().AppendLine(S(hosted, "note"));
            }
        }
        text.AppendLine().AppendLine("RECORDED EVIDENCE").AppendLine();
        return text.Append(JsonSerializer.Serialize(alert, new JsonSerializerOptions { WriteIndented = true })).ToString();
    }
    private async Task ExportReport()
    {
        using var dialog = new SaveFileDialog { Title = "Save sentient1 report", Filter = "HTML report (*.html)|*.html|JSON evidence (*.json)|*.json", FileName = "sentient1-report-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".html", OverwritePrompt = true };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        await Engine.CaptureAsync("report", "--format", dialog.FilterIndex == 2 ? "json" : "html", "--output", dialog.FileName, "--overwrite");
        Log("Report saved: " + dialog.FileName + " · command lines excluded; paths and network evidence retained.");
    }

    // Exercises actual views, actual setup validation and a real read-only elevated
    // diagnostic. It never applies settings or plants test detections.
    private async Task RunUiTest()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "desktop-ui-test.txt");
        try
        {
            foreach (var name in pages.Keys) await Navigate(name);
            setup.VerifyScrolling();
            await setup.ValidateCurrentAsync();
            await RunOperation(new EngineRequest("doctor"));
            WindowState = FormWindowState.Minimized;
            if (!ShowInTaskbar || !Visible || !tray.Visible) throw new InvalidOperationException("Minimise visibility failed.");
            RestoreWindow(); await Navigate("Overview");
            File.WriteAllText(path, "PASS: all five pages; real setup validation; elevated diagnostics streamed in-window; minimise/taskbar/tray/restore; hidden scrollbars with wheel/keyboard navigation.\n");
        }
        catch (Exception ex) { File.WriteAllText(path, ex.ToString()); Log("ERROR  UI verification: " + ex.Message); }
    }
    internal static string S(JsonElement value, string name) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() ?? "" : "";
    internal static int N(JsonElement value, string name) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var p) && p.TryGetInt32(out var n) ? n : 0;
    internal static bool B(JsonElement value, string name) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.True;
    internal static IEnumerable<JsonElement> Array(JsonElement value, string name) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.Array ? p.EnumerateArray() : [];
    private static string LocalTime(string value) => DateTimeOffset.TryParse(value, out var time) ? time.ToLocalTime().ToString("dd MMM HH:mm:ss") : value;
    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000))
        {
            var enabled = 1;
            _ = DwmSetWindowAttribute(Handle, 20, ref enabled, sizeof(int));
            var caption = ColorTranslator.ToWin32(Theme.Background);
            var foreground = ColorTranslator.ToWin32(Theme.Text);
            _ = DwmSetWindowAttribute(Handle, 35, ref caption, sizeof(int));
            _ = DwmSetWindowAttribute(Handle, 36, ref foreground, sizeof(int));
        }
    }
    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr window, int attribute, ref int value, int size);

    protected override void Dispose(bool disposing)
    {
        if (disposing) { timer.Dispose(); tray.Visible = false; tray.ContextMenuStrip?.Dispose(); tray.Dispose(); appIcon.Dispose(); }
        base.Dispose(disposing);
    }
}
