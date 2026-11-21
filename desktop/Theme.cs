using System.Drawing.Drawing2D;

namespace Sentient1;

internal static class Theme
{
    internal static readonly Color Background = Color.FromArgb(8, 14, 13);
    internal static readonly Color Surface = Color.FromArgb(14, 24, 21);
    internal static readonly Color Raised = Color.FromArgb(20, 34, 28);
    internal static readonly Color Border = Color.FromArgb(38, 64, 51);
    internal static readonly Color Text = Color.FromArgb(222, 237, 226);
    internal static readonly Color Muted = Color.FromArgb(139, 164, 149);
    internal static readonly Color Green = Color.FromArgb(119, 244, 147);
    internal static readonly Color Amber = Color.FromArgb(244, 194, 105);
    internal static readonly Color Red = Color.FromArgb(255, 128, 128);

    internal static Label Label(string text, float size = 10, Color? color = null, bool bold = false) => new()
    {
        Text = text,
        AutoSize = true,
        ForeColor = color ?? Text,
        Font = new Font("Segoe UI", size, bold ? FontStyle.Bold : FontStyle.Regular),
        Margin = new Padding(0, 0, 0, 8)
    };
    internal static Button Button(string text, bool primary = false)
    {
        var b = new Button
        {
            Text = text,
            AutoSize = true,
            MinimumSize = new Size(100, 36),
            FlatStyle = FlatStyle.Flat,
            BackColor = primary ? Green : Raised,
            ForeColor = primary ? Background : Text,
            Padding = new Padding(10, 5, 10, 5),
            Margin = new Padding(0, 0, 8, 6),
            Cursor = Cursors.Hand,
            UseVisualStyleBackColor = false
        };
        b.FlatAppearance.BorderColor = primary ? Green : Border;
        b.FlatAppearance.MouseOverBackColor = primary ? Color.FromArgb(158, 255, 180) : Color.FromArgb(32, 57, 43);
        return b;
    }
    internal static FlowLayoutPanel Flow(bool vertical = false) => new()
    {
        Dock = DockStyle.Top,
        AutoSize = true,
        WrapContents = !vertical,
        FlowDirection = vertical ? FlowDirection.TopDown : FlowDirection.LeftToRight,
        Margin = Padding.Empty
    };
    internal static TextBox TextBox(string hint = "", bool password = false) => new()
    {
        Width = 260,
        BackColor = Raised,
        ForeColor = Text,
        BorderStyle = BorderStyle.FixedSingle,
        PlaceholderText = hint,
        UseSystemPasswordChar = password,
        Margin = new Padding(0, 0, 12, 8)
    };
    internal static ComboBox Combo(params string[] items)
    {
        var c = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 230, BackColor = Raised, ForeColor = Text, FlatStyle = FlatStyle.Flat, Margin = new Padding(0, 0, 12, 8) };
        c.Items.AddRange(items); if (items.Length > 0) c.SelectedIndex = 0;
        return c;
    }
    internal static DataGridView Grid(params string[] columns)
    {
        var g = new WheelGrid
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            AllowUserToResizeRows = false,
            RowHeadersVisible = false,
            MultiSelect = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
            BackgroundColor = Surface,
            BorderStyle = BorderStyle.None,
            EnableHeadersVisualStyles = false,
            GridColor = Border,
            ColumnHeadersHeight = 38,
            AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.AllCells,
            ClipboardCopyMode = DataGridViewClipboardCopyMode.EnableAlwaysIncludeHeaderText
        };
        g.DefaultCellStyle = new DataGridViewCellStyle { BackColor = Surface, ForeColor = Text, SelectionBackColor = Color.FromArgb(35, 65, 46), SelectionForeColor = Color.White, Padding = new Padding(7), WrapMode = DataGridViewTriState.True };
        g.ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle { BackColor = Raised, ForeColor = Green, Font = new Font("Segoe UI", 9, FontStyle.Bold), Padding = new Padding(7) };
        foreach (var name in columns) g.Columns.Add(name, name);
        return g;
    }
    internal static TextBox ReadOnlyText(bool mono = false) => new WheelTextBox()
    {
        Dock = DockStyle.Fill,
        Multiline = true,
        ReadOnly = true,
        ScrollBars = ScrollBars.None,
        BorderStyle = BorderStyle.None,
        BackColor = Surface,
        ForeColor = Text,
        Font = new Font(mono ? "Consolas" : "Segoe UI", 10)
    };
}

internal sealed class TechHeader : Panel
{
    internal TechHeader() { DoubleBuffered = true; BackColor = Theme.Background; }
    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        using var grid = new Pen(Color.FromArgb(22, 43, 32));
        for (var x = Width / 2; x < Width; x += 24) e.Graphics.DrawLine(grid, x, 0, x, Height);
        for (var y = 0; y < Height; y += 24) e.Graphics.DrawLine(grid, Width / 2, y, Width, y);
        using var line = new Pen(Theme.Green, 2);
        e.Graphics.DrawLine(line, 0, Height - 2, 74, Height - 2);
        using var edge = new Pen(Theme.Border);
        e.Graphics.DrawLine(edge, 74, Height - 2, Width, Height - 2);
    }
}
