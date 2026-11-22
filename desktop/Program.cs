using System.Text.Json;

namespace Sentient1;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        if (args.Length == 3 && args[0] == "--worker" && int.TryParse(args[2], out var parent))
        {
            try { return Engine.WorkerAsync(args[1], parent).GetAwaiter().GetResult(); }
            catch { return 1; }
        }
        if (args.Length == 2 && args[0] == "--alert")
        {
            try
            {
                _ = Engine.Arguments(new EngineRequest("freeze", args[1]));
                Application.Run(new AlertForm(args[1]));
                return 0;
            }
            catch { return 1; }
        }
        if (args.Contains("--smoke-test", StringComparer.Ordinal))
        {
            try
            {
                using var form = new MainForm(); form.CreateControl();
                using var document = JsonDocument.Parse(Engine.CaptureAsync("status", "--json").GetAwaiter().GetResult());
                if (document.RootElement.GetProperty("product").GetString() != "sentient1" || !form.ShowInTaskbar || form.Icon is null) return 2;
                foreach (var operation in new[] { "doctor", "repair", "test", "release", "uninstall" }) _ = Engine.Arguments(new EngineRequest(operation));
                foreach (var operation in new[] { "freeze", "resume", "trust", "kill" }) _ = Engine.Arguments(new EngineRequest(operation, "20261122-test"));
                using var alertForm = new AlertForm("20261122-test"); alertForm.CreateControl();
                foreach (var bad in new[] { new EngineRequest("cmd"), new EngineRequest("freeze", "../escape"), new EngineRequest("freeze"), new EngineRequest("kill", "../escape"), new EngineRequest("doctor", "extra"), new EngineRequest("apply") })
                {
                    try { _ = Engine.Arguments(bad); throw new Exception("Unsafe operation accepted."); }
                    catch (InvalidOperationException) { }
                }
                File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "desktop-smoke-test.txt"), "PASS: native pages, shield, taskbar, real engine snapshot and worker allowlist.\n");
                return 0;
            }
            catch (Exception ex) { File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "desktop-smoke-test.txt"), ex.ToString()); return 1; }
        }
        Application.Run(new MainForm(args.Contains("--ui-test", StringComparer.Ordinal)));
        return 0;
    }
}
