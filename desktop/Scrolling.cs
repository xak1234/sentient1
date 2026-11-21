using System.Runtime.InteropServices;

namespace Sentient1;

internal static class WheelScroll
{
    internal static int Lines(int delta, int pageLines)
    {
        var lines = SystemInformation.MouseWheelScrollLines;
        return -(delta / SystemInformation.MouseWheelScrollDelta) * (lines < 0 ? Math.Max(1, pageLines) : lines);
    }
    internal static void Text(Control control, MouseEventArgs e)
    {
        var lines = Lines(e.Delta, Math.Max(1, control.Height / control.Font.Height - 1));
        _ = SendMessage(control.Handle, 0x00B6, IntPtr.Zero, (IntPtr)lines); // EM_LINESCROLL
        if (e is HandledMouseEventArgs handled) handled.Handled = true;
    }
    internal static void SendWheel(Control control, int delta) => _ = SendMessage(control.Handle, 0x020A, (IntPtr)(delta << 16), IntPtr.Zero);
    internal static void SendKey(Control control, Keys key) { control.Focus(); _ = SendMessage(control.Handle, 0x0100, (IntPtr)(int)key, IntPtr.Zero); }
    [DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr window, int message, IntPtr wParam, IntPtr lParam);
}

internal sealed class WheelTextBox : TextBox
{
    internal WheelTextBox() { ScrollBars = ScrollBars.None; }
    protected override void OnMouseWheel(MouseEventArgs e) => WheelScroll.Text(this, e);
}

internal sealed class WheelTerminal : RichTextBox
{
    internal WheelTerminal() { ScrollBars = RichTextBoxScrollBars.None; WordWrap = true; }
    protected override void OnMouseWheel(MouseEventArgs e) => WheelScroll.Text(this, e);
}

internal sealed class WheelGrid : DataGridView
{
    internal WheelGrid() { ScrollBars = ScrollBars.None; }
    protected override void OnMouseWheel(MouseEventArgs e)
    {
        if (RowCount == 0) return;
        var first = Math.Max(0, FirstDisplayedScrollingRowIndex);
        var visible = Math.Max(1, DisplayedRowCount(false));
        var target = Math.Clamp(first + WheelScroll.Lines(e.Delta, visible), 0, Math.Max(0, RowCount - visible));
        if (target != first) FirstDisplayedScrollingRowIndex = target;
        else
        {
            for (Control? parent = Parent; parent is not null; parent = parent.Parent)
                if (parent is WheelViewport viewport) { viewport.ScrollWheel(e.Delta); break; }
        }
        if (e is HandledMouseEventArgs handled) handled.Handled = true;
    }
    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (!e.Control && !e.Alt && !e.Shift && RowCount > 0 && e.KeyCode is Keys.Up or Keys.Down or Keys.PageUp or Keys.PageDown or Keys.Home or Keys.End)
        {
            var visible = Math.Max(1, DisplayedRowCount(false)); var current = CurrentCell?.RowIndex ?? 0;
            var target = e.KeyCode switch
            {
                Keys.Up => current - 1,
                Keys.Down => current + 1,
                Keys.PageUp => current - visible,
                Keys.PageDown => current + visible,
                Keys.Home => 0,
                Keys.End => RowCount - 1,
                _ => current
            };
            target = Math.Clamp(target, 0, RowCount - 1);
            CurrentCell = Rows[target].Cells[CurrentCell?.ColumnIndex ?? 0];
            var first = Math.Max(0, FirstDisplayedScrollingRowIndex);
            if (target < first) FirstDisplayedScrollingRowIndex = target;
            else if (target >= first + visible) FirstDisplayedScrollingRowIndex = Math.Max(0, target - visible + 1);
            e.Handled = true; e.SuppressKeyPress = true; return;
        }
        base.OnKeyDown(e);
    }
}

// A clipped content viewport, with no native scrollbar styles. Moving the content
// keeps wheel, keyboard and focus navigation independent of visible scrollbars.
internal class WheelViewport : UserControl
{
    private Control? content;
    private int offset;
    private bool arranging;
    internal int ScrollOffset => offset;

    protected WheelViewport() { AutoScroll = false; TabStop = true; DoubleBuffered = true; }
    protected void SetContent(Control body)
    {
        content = body; body.Dock = DockStyle.None; Controls.Add(body);
        body.SizeChanged += (_, _) => Arrange();
        TrackFocus(body); Arrange();
    }
    private void TrackFocus(Control root)
    {
        root.Enter += (_, _) => Reveal(root);
        if (root is Label or Panel) root.MouseDown += (_, _) => Focus();
        root.ControlAdded += (_, e) => { if (e.Control is { } control) TrackFocus(control); };
        foreach (Control child in root.Controls) TrackFocus(child);
    }
    private void Reveal(Control control)
    {
        if (content is null || !control.Focused) return;
        var bounds = RectangleToClient(control.RectangleToScreen(control.ClientRectangle));
        if (bounds.Top < 8) ScrollTo(offset + bounds.Top - 8);
        else if (bounds.Bottom > ClientSize.Height - 8) ScrollTo(offset + bounds.Bottom - ClientSize.Height + 8);
    }
    private void Arrange()
    {
        if (content is null || arranging) return;
        arranging = true;
        try
        {
            var width = Math.Max(1, ClientSize.Width);
            content.MinimumSize = new Size(width, 0); content.MaximumSize = new Size(width, 0); content.Width = width;
            ScrollTo(offset);
        }
        finally { arranging = false; }
    }
    protected override void OnSizeChanged(EventArgs e) { base.OnSizeChanged(e); Arrange(); }
    private void ScrollTo(int value)
    {
        if (content is null) return;
        offset = Math.Clamp(value, 0, Math.Max(0, content.Height - ClientSize.Height));
        content.Location = new Point(0, -offset);
    }
    internal void ScrollWheel(int delta) => ScrollTo(offset + WheelScroll.Lines(delta, Math.Max(1, ClientSize.Height / 24 - 1)) * 24);
    protected override void OnMouseWheel(MouseEventArgs e)
    {
        ScrollWheel(e.Delta); if (e is HandledMouseEventArgs handled) handled.Handled = true;
    }
    protected override bool IsInputKey(Keys keyData) => (keyData & Keys.KeyCode) is Keys.Up or Keys.Down or Keys.PageUp or Keys.PageDown or Keys.Home or Keys.End || base.IsInputKey(keyData);
    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (!e.Control && !e.Alt && !e.Shift)
        {
            var target = e.KeyCode switch
            {
                Keys.Up => offset - 24,
                Keys.Down => offset + 24,
                Keys.PageUp => offset - ClientSize.Height + 24,
                Keys.PageDown => offset + ClientSize.Height - 24,
                Keys.Home => 0,
                Keys.End => int.MaxValue,
                _ => offset
            };
            if (target != offset) { ScrollTo(target); e.Handled = true; e.SuppressKeyPress = true; }
        }
        base.OnKeyDown(e);
    }
}
