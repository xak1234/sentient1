using System.Text.Json;

namespace Sentient1;

internal sealed class SetupView : WheelViewport
{
    private readonly Action<string> log;
    private readonly Action<string, Func<Task>> confirm;
    private readonly Func<EngineRequest, Task> run;
    private readonly Label account = Theme.Label("Loading your current configuration…", 11, Theme.Muted);
    private readonly ComboBox policy = Theme.Combo("Balanced", "Alert only", "Strict");
    private readonly NumericUpDown days = new() { Minimum = 0, Maximum = 30, Width = 80, BackColor = Theme.Raised, ForeColor = Theme.Text };
    private readonly CheckBox keepLearning = Check("Keep the current learning end date");
    private readonly CheckBox clean = Check("Keep decoys out of Windows Recent items");
    private readonly CheckBox instant = Check("Enable optional oplock timing inference");
    private readonly ComboBox phone = Theme.Combo("Keep existing notifications", "Off", "ntfy", "Discord", "Pushover", "Email");
    private readonly FlowLayoutPanel phoneFields = Theme.Flow();
    private readonly Dictionary<string, TextBox> inputs = [];
    private readonly TextBox canary = Theme.TextBox("Optional canary email address");
    private readonly CheckBox tls = Check("Implicit TLS (usually port 465)");
    private readonly DataGridView baits = Theme.Grid("Decoy", "Category", "Details / availability");
    private readonly Label selection = Theme.Label("", 10, Theme.Green);
    private JsonElement plan;
    private bool loading;
    internal bool Loaded => plan.ValueKind == JsonValueKind.Object;

    internal SetupView(Action<string> log, Action<string, Func<Task>> confirm, Func<EngineRequest, Task> run)
    {
        this.log = log; this.confirm = confirm; this.run = run;
        Dock = DockStyle.Fill; BackColor = Theme.Background; ForeColor = Theme.Text; AutoScroll = false;
        var layout = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 1, Padding = new Padding(0, 0, 14, 16) };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        void Add(Control c) { c.Dock = DockStyle.Top; c.Margin = new Padding(0, 0, 0, 12); layout.Controls.Add(c, 0, layout.RowCount++); }
        var heading = Theme.Flow(true); heading.Controls.Add(account);
        var reload = Theme.Button("Reload saved settings"); reload.Click += async (_, _) => await Guard(LoadAsync); heading.Controls.Add(reload); Add(heading);
        var response = Card("01  RESPONSE POLICY");
        var choices = Theme.Flow(); choices.Controls.Add(policy); choices.Controls.Add(Theme.Label("Learning days", 10, Theme.Muted)); choices.Controls.Add(days); response.Controls.Add(choices);
        response.Controls.Add(Note("Balanced freezes and blocks critical readers. Alert only records and notifies. Strict can isolate the whole PC. Learning delays lower-severity actions only; critical responses stay enabled."));
        keepLearning.CheckedChanged += (_, _) => days.Enabled = !keepLearning.Checked;
        response.Controls.Add(keepLearning); response.Controls.Add(clean); response.Controls.Add(instant);
        response.Controls.Add(Note("Windows file auditing identifies readers by default. Oplock timing inference is faster but can misattribute access; it remains optional.")); Add(response);
        var decoys = Card("02  DECOY SELECTION");
        var chooser = Theme.Flow();
        var recommended = Theme.Button("Recommended"); recommended.Click += (_, _) => SelectBaits(true);
        var all = Theme.Button("All available"); all.Click += (_, _) => SelectBaits(false);
        chooser.Controls.Add(recommended); chooser.Controls.Add(all); chooser.Controls.Add(selection); decoys.Controls.Add(chooser);
        baits.Dock = DockStyle.None; baits.Height = 330; baits.Width = 760; baits.ReadOnly = false;
        foreach (DataGridViewColumn column in baits.Columns) column.ReadOnly = true;
        baits.Columns.Insert(0, new DataGridViewCheckBoxColumn { Name = "Use", HeaderText = "Use", Width = 55, AutoSizeMode = DataGridViewAutoSizeColumnMode.None });
        baits.Columns[1].FillWeight = 28; baits.Columns[2].FillWeight = 18; baits.Columns[3].FillWeight = 54;
        baits.CurrentCellDirtyStateChanged += (_, _) => { if (baits.IsCurrentCellDirty) baits.CommitEdit(DataGridViewDataErrorContexts.Commit); };
        baits.CellValueChanged += (_, _) => UpdateCount();
        decoys.Controls.Add(baits); decoys.Controls.Add(Note("Unavailable profiles belong to real applications and cannot be selected. Existing custom decoys are preserved. Browser-extension decoys require a selected browser host.")); Add(decoys);
        var notifications = Card("03  NOTIFICATIONS & CANARY TOKENS");
        notifications.Controls.Add(phone); notifications.Controls.Add(phoneFields);
        phone.SelectedIndexChanged += (_, _) => BuildPhoneFields();
        notifications.Controls.Add(Note("Existing credentials stay protected and are never loaded into these fields. Changing a provider sends one test notification when you apply."));
        notifications.Controls.Add(canary);
        notifications.Controls.Add(Note("Optional: creates external canary tokens using this email. Leave blank to keep existing canaries unchanged.")); Add(notifications);
        var applyRow = Theme.Flow(); var validate = Theme.Button("Validate settings"); var apply = Theme.Button("Review & apply", true);
        validate.Click += async (_, _) => await Guard(async () => log((await Engine.CaptureInputAsync(Request(), "desktop", "validate")).Trim()));
        apply.Click += async (_, _) => await Guard(async () =>
        {
            var request = Request();
            log((await Engine.CaptureInputAsync(request, "desktop", "validate")).Trim());
            var extra = phone.SelectedIndex > 1 ? " A test notification will be sent to the new provider." : "";
            if (!string.IsNullOrWhiteSpace(canary.Text)) extra += " External canary tokens will be requested for the supplied email.";
            confirm($"Apply {policy.Text} with {Selected().Count} catalog decoys? The monitor pauses briefly while settings and decoys are updated.{extra}", async () =>
            {
                await run(new EngineRequest("apply", Setup: request));
                await LoadAsync();
            });
        });
        applyRow.Controls.Add(validate); applyRow.Controls.Add(apply); Add(applyRow);
        SetContent(layout);
        // Keep all card content inside the scrollable viewport at every supported DPI.
        layout.SizeChanged += (_, _) =>
        {
            var width = Math.Max(360, layout.ClientSize.Width - 48);
            baits.Width = width; phoneFields.MaximumSize = new Size(width, 0);
            foreach (var card in layout.Controls.OfType<FlowLayoutPanel>())
                foreach (var label in card.Controls.OfType<Label>()) label.MaximumSize = new Size(width, 0);
        };
    }

    private static CheckBox Check(string text) => new() { Text = text, AutoSize = true, ForeColor = Theme.Text, Margin = new Padding(0, 4, 0, 8) };
    private static Label Note(string text) { var l = Theme.Label(text, 9.5F, Theme.Muted); l.MaximumSize = new Size(760, 0); return l; }
    private static FlowLayoutPanel Card(string title)
    {
        var c = Theme.Flow(true); c.BackColor = Theme.Surface; c.Padding = new Padding(16);
        c.Controls.Add(Theme.Label(title, 10, Theme.Green, true)); return c;
    }
    private async Task Guard(Func<Task> operation)
    {
        if (loading) return;
        try { await operation(); } catch (Exception ex) { log("ERROR  " + ex.Message); }
    }

    internal async Task LoadAsync()
    {
        loading = true; Enabled = false;
        try
        {
            using var doc = JsonDocument.Parse(await Engine.CaptureAsync("desktop", "plan"));
            plan = doc.RootElement.Clone();
            account.Text = $"Protecting {MainForm.S(plan, "user")}  ·  {MainForm.N(plan, "customCount")} custom decoys preserved";
            var preset = MainForm.S(plan, "policy");
            if (preset == "custom" && !policy.Items.Contains("Custom (preserve)")) policy.Items.Add("Custom (preserve)");
            policy.SelectedIndex = preset switch { "alert" => 1, "strict" => 2, "custom" => 3, _ => 0 };
            days.Value = Math.Clamp(MainForm.N(plan, "learningDays"), 0, 30);
            keepLearning.Checked = MainForm.B(plan, "installed");
            clean.Checked = MainForm.B(plan, "cleanRecent"); instant.Checked = MainForm.B(plan, "instant");
            baits.Rows.Clear();
            foreach (var bait in MainForm.Array(plan, "baits"))
            {
                var available = MainForm.B(bait, "available");
                var detail = available ? MainForm.S(bait, "description") : "UNAVAILABLE · " + MainForm.S(bait, "reason");
                var row = baits.Rows[baits.Rows.Add(MainForm.B(bait, "selected"), MainForm.S(bait, "name"), MainForm.S(bait, "category"), detail)];
                row.Tag = bait.Clone(); row.Cells[0].ReadOnly = !available;
                if (!available) row.DefaultCellStyle.ForeColor = Theme.Muted;
            }
            phone.SelectedIndex = 0; BuildPhoneFields(); canary.Clear(); UpdateCount();
        }
        finally { loading = false; Enabled = true; }
    }

    private void SelectBaits(bool recommended)
    {
        foreach (DataGridViewRow row in baits.Rows)
            if (row.Tag is JsonElement bait) row.Cells[0].Value = MainForm.B(bait, "available") && (!recommended || MainForm.B(bait, "recommended"));
        UpdateCount();
    }
    private List<string> Selected() => baits.Rows.Cast<DataGridViewRow>().Where(row => row.Cells[0].Value is true).Select(row => MainForm.S((JsonElement)row.Tag!, "id")).ToList();
    private void UpdateCount() => selection.Text = $"{Selected().Count} selected";

    private void BuildPhoneFields()
    {
        foreach (var old in phoneFields.Controls.Cast<Control>().ToArray()) { if (old != tls) old.Dispose(); }
        phoneFields.Controls.Clear(); inputs.Clear();
        void Field(string name, string label, bool secret = false, string value = "")
        {
            var group = Theme.Flow(true); group.Dock = DockStyle.None;
            var field = Theme.TextBox(label, secret); field.Text = value; inputs[name] = field;
            group.Controls.Add(Theme.Label(label, 9, Theme.Muted)); group.Controls.Add(field); phoneFields.Controls.Add(group);
        }
        switch (phone.SelectedIndex)
        {
            case 2: Field("server", "HTTPS server", value: "https://ntfy.sh"); Field("topic", "Topic"); Field("token", "Access token (optional)", true); break;
            case 3: Field("webhookUrl", "Discord webhook URL", true); break;
            case 4: Field("appToken", "Application token", true); Field("userKey", "User key", true); break;
            case 5:
                Field("host", "SMTP host"); Field("port", "Port", value: "587"); Field("username", "Username"); Field("password", "Password", true);
                Field("from", "From email"); Field("to", "To email"); phoneFields.Controls.Add(tls); break;
        }
    }
    private string Request()
    {
        if (!Loaded) throw new InvalidOperationException("Reload setup first.");
        baits.EndEdit();
        string Value(string key) => inputs.TryGetValue(key, out var field) ? field.Text.Trim() : "";
        var kind = phone.SelectedIndex switch { 2 => "ntfy", 3 => "discord", 4 => "pushover", 5 => "email", _ => "" };
        object phoneConfig = kind switch
        {
            "ntfy" => new { kind, ntfy = new { server = Value("server"), topic = Value("topic"), token = Value("token") } },
            "discord" => new { kind, discord = new { webhookUrl = Value("webhookUrl") } },
            "pushover" => new { kind, pushover = new { appToken = Value("appToken"), userKey = Value("userKey") } },
            "email" => new { kind, email = new { host = Value("host"), port = int.TryParse(Value("port"), out var port) ? port : 0, username = Value("username"), password = inputs["password"].Text, from = Value("from"), to = Value("to"), implicitTls = tls.Checked } },
            _ => new { kind }
        };
        return JsonSerializer.Serialize(new
        {
            revision = MainForm.S(plan, "revision"),
            userSid = MainForm.S(plan, "userSid"),
            policy = policy.SelectedIndex switch { 1 => "alert", 2 => "strict", 3 => "custom", _ => "balanced" },
            learningDays = (int)days.Value,
            keepLearning = keepLearning.Checked,
            cleanRecent = clean.Checked,
            instant = instant.Checked,
            baits = Selected(),
            phoneMode = phone.SelectedIndex switch { 0 => "keep", 1 => "none", _ => "replace" },
            phone = phoneConfig,
            canaryEmail = canary.Text.Trim()
        });
    }

    internal void VerifyScrolling()
    {
        Focus(); WheelScroll.SendKey(this, Keys.Home);
        WheelScroll.SendWheel(this, -120);
        if (ScrollOffset <= 0) throw new InvalidOperationException("Setup mouse-wheel scrolling failed.");
        var afterWheel = ScrollOffset; WheelScroll.SendKey(this, Keys.PageDown);
        if (ScrollOffset <= afterWheel) throw new InvalidOperationException("Setup keyboard scrolling failed.");
        WheelScroll.SendKey(this, Keys.Home);
        if (ScrollOffset != 0) throw new InvalidOperationException("Setup Home key failed.");
        if (baits.RowCount > baits.DisplayedRowCount(false))
        {
            baits.FirstDisplayedScrollingRowIndex = 0;
            WheelScroll.SendWheel(baits, -120);
            if (baits.FirstDisplayedScrollingRowIndex <= 0) throw new InvalidOperationException("Decoy table mouse-wheel scrolling failed.");
            WheelScroll.SendKey(baits, Keys.End);
            if (baits.CurrentCell?.RowIndex != baits.RowCount - 1) throw new InvalidOperationException("Decoy table keyboard scrolling failed.");
            WheelScroll.SendKey(baits, Keys.Home); Focus(); WheelScroll.SendKey(this, Keys.Home);
        }
        if (baits.ScrollBars != ScrollBars.None || AutoScroll) throw new InvalidOperationException("Unexpected native scrollbar.");
    }

    internal async Task ValidateCurrentAsync() => log((await Engine.CaptureInputAsync(Request(), "desktop", "validate")).Trim());
}
