namespace Sentient1;

// Paired staircases indicate a recent running-service heartbeat. They are a
// status animation, not a fabricated scan count or a file-read activity meter.
internal sealed class ActivitySignal : Control
{
    private readonly System.Windows.Forms.Timer clock = new() { Interval = 140 };
    private int phase;
    private bool running;
    private bool healthy;
    private DateTimeOffset heartbeat;
    private DateTimeOffset refreshed;

    internal ActivitySignal()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.SupportsTransparentBackColor, true);
        BackColor = Color.Transparent; Size = new Size(224, 64);
        AccessibleName = "Monitor activity";
        Font = new Font("Consolas", 8);
        clock.Tick += (_, _) => { phase = Active ? (phase + 1) % 18 : 0; Invalidate(); };
        clock.Start();
    }

    private bool Active => running && DateTimeOffset.UtcNow - heartbeat <= TimeSpan.FromMinutes(3)
        && heartbeat <= DateTimeOffset.UtcNow.AddMinutes(1)
        && DateTimeOffset.UtcNow - refreshed <= TimeSpan.FromSeconds(20);

    internal void UpdateStatus(bool serviceRunning, bool checksHealthy, DateTimeOffset serviceHeartbeat)
    {
        running = serviceRunning; healthy = checksHealthy; heartbeat = serviceHeartbeat; refreshed = DateTimeOffset.UtcNow;
        if (!Active) phase = 0;
        AccessibleDescription = Active ? "Monitor service running with a recent heartbeat." : "Monitor activity is stopped, unavailable or stale.";
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        var active = Active;
        var accent = healthy ? Theme.Green : Theme.Amber;
        using var dim = new SolidBrush(Theme.Border);
        using var lit = new SolidBrush(accent);
        using var peak = new SolidBrush(Color.FromArgb(220, 255, 228));
        // Five ascending columns, an open gap, then five descending columns.
        for (var side = 0; side < 2; side++)
        {
            for (var column = 0; column < 5; column++)
            {
                var count = side == 0 ? column + 1 : 5 - column;
                var step = side == 0 ? column : column + 8;
                var enabled = active && phase >= step && phase < 15;
                var x = 14 + side * 110 + column * 16;
                for (var block = 0; block < count; block++)
                {
                    var rectangle = new Rectangle(x, 35 - block * 8, 11, 6);
                    e.Graphics.FillRectangle(enabled ? phase == step ? peak : lit : dim, rectangle);
                }
            }
        }
        var caption = active ? healthy ? "MONITOR ACTIVE" : "MONITOR RUNNING" : "ACTIVITY PAUSED";
        TextRenderer.DrawText(e.Graphics, caption, Font, new Rectangle(0, 47, Width, 15), active ? accent : Theme.Muted, TextFormatFlags.HorizontalCenter | TextFormatFlags.NoPadding);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) { clock.Stop(); clock.Dispose(); }
        base.Dispose(disposing);
    }
}
