using System.ComponentModel;
using System.Text.Json;

namespace Sentient1;

// One alert, with the same verified administrator helper as the dashboard.
internal sealed class AlertForm : Form
{
    private readonly string alertId;
    private readonly System.Windows.Forms.Timer timer = new() { Interval = 5000 };
    private readonly Label title = Theme.Label("Reading detection…", 16, Theme.Green, true);
    private readonly Label summary = Theme.Label("", 10, Theme.Text);
    private readonly Label availability = Theme.Label("Checking whether this reader can be paused…", 10, Theme.Amber);
    private readonly TextBox evidence = Theme.ReadOnlyText();
    private readonly TextBox output = Theme.ReadOnlyText(true);
    private readonly Button freeze = Theme.Button("Freeze once");
    private readonly Button resume = Theme.Button("Resume once");
    private readonly Button trust = Theme.Button("Trust reader");
    private readonly Button close = Theme.Button("Keep alerting / Close");
    private JsonElement alert;
    private bool acting;
    private bool refreshing;

    internal AlertForm(string id)
    {
        alertId = id;
        Text = "sentient1 · Detection";
        Icon = (Icon)SystemIcons.Shield.Clone();
        BackColor = Theme.Background; ForeColor = Theme.Text; Font = new Font("Segoe UI", 10);
        Size = new Size(960, 820); MinimumSize = new Size(760, 640);
        StartPosition = FormStartPosition.CenterScreen; ShowInTaskbar = true; TopMost = true;
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 6, Padding = new Padding(22) };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 80));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 78));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 88));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        foreach (var label in new[] { title, summary, availability }) { label.AutoSize = false; label.Dock = DockStyle.Fill; }
        layout.Controls.Add(title, 0, 0); layout.Controls.Add(summary, 0, 1); layout.Controls.Add(availability, 0, 2);
        layout.Controls.Add(evidence, 0, 3); layout.Controls.Add(output, 0, 4);
        output.ForeColor = Theme.Green; output.BackColor = Theme.Background;
        var actions = Theme.Flow(); actions.Padding = new Padding(0, 12, 0, 0);
        actions.Controls.AddRange([freeze, resume, trust, close]); layout.Controls.Add(actions, 0, 5);
        Controls.Add(layout);
        freeze.Enabled = resume.Enabled = trust.Enabled = false;
        freeze.Click += async (_, _) => await Act("freeze");
        resume.Click += async (_, _) => await Act("resume");
        trust.Click += async (_, _) =>
        {
            var question = SharedHost() ? "Approve this incident and resume the reader once? No permanent trust rule will be added for a shared host." : "Trust and resume this reader? Only continue after verifying its evidence and publisher.";
            if (MessageBox.Show(this, question, "sentient1", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes) await Act("trust");
        };
        close.Click += (_, _) => Close();
        CancelButton = close; // Enter never accepts Freeze or Trust by default.
        Shown += async (_, _) => { await RefreshAlert(); if (!IsDisposed) timer.Start(); };
        timer.Tick += async (_, _) => await RefreshAlert();
        FormClosing += (_, e) => { if (acting) e.Cancel = true; };
    }

    private bool SharedHost() => alert.ValueKind == JsonValueKind.Object && alert.TryGetProperty("process", out var process) &&
        process.ValueKind == JsonValueKind.Object && process.TryGetProperty("hosted", out var hosted) && hosted.ValueKind == JsonValueKind.Object;

    private async Task RefreshAlert()
    {
        if (refreshing || acting || IsDisposed) return;
        refreshing = true;
        freeze.Enabled = resume.Enabled = trust.Enabled = false;
        try
        {
            using var document = JsonDocument.Parse(await Engine.CaptureAsync("alerts", "json", alertId));
            if (IsDisposed) return;
            alert = document.RootElement.Clone();
            title.Text = MainForm.S(alert, "title"); summary.Text = MainForm.S(alert, "summary");
            if (alert.TryGetProperty("process", out var process) && MainForm.S(process, "displayName") is { Length: > 0 } reader)
                title.Text = reader;
            evidence.Text = MainForm.FormatEvidence(alert);
            var controls = alert.GetProperty("controls");
            freeze.Enabled = MainForm.B(controls, "canFreeze"); resume.Enabled = MainForm.B(controls, "frozen"); trust.Enabled = true;
            close.Text = MainForm.B(controls, "frozen") ? "Close (stays frozen)" : "Keep alerting / Close";
            availability.Text = "Freeze once: " + MainForm.S(controls, "freezeReason") + "\nPauses this process until Resume once. All components in a shared host pause together.";
            trust.Text = SharedHost() ? "Approve once" : "Trust reader";
        }
        catch (Exception ex)
        {
            if (IsDisposed) return;
            freeze.Enabled = resume.Enabled = trust.Enabled = false;
            availability.Text = "Actions unavailable: " + ex.Message;
        }
        finally { refreshing = false; }
    }

    private async Task Act(string operation)
    {
        if (acting || refreshing) return;
        acting = true; timer.Stop();
        freeze.Enabled = resume.Enabled = trust.Enabled = close.Enabled = false;
        output.Text = "> " + operation + " · waiting for the Windows administrator helper…\r\n";
        try { await Engine.RunAsync(new EngineRequest(operation, alertId), Log); Log("Completed."); }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) { Log("Administrator request cancelled. No operation was started."); }
        catch (Exception ex) { Log("ERROR  " + ex.Message); }
        finally
        {
            acting = false;
            if (!IsDisposed) { close.Enabled = true; await RefreshAlert(); timer.Start(); }
        }
    }

    private void Log(string text)
    {
        if (IsDisposed) return;
        if (InvokeRequired) { BeginInvoke(() => Log(text)); return; }
        output.AppendText(text + Environment.NewLine);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) { timer.Dispose(); Icon?.Dispose(); }
        base.Dispose(disposing);
    }
}
