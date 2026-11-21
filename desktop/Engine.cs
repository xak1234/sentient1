using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Sentient1;

internal sealed record EngineRequest(string Operation, string? AlertId = null, string? Setup = null);
internal sealed record EngineMessage(string Kind, string Text, int ExitCode = 0);

internal static class Engine
{
    internal static string Executable
    {
        get
        {
            var bundled = Path.Combine(AppContext.BaseDirectory, "sentient1.exe");
            if (File.Exists(bundled)) return bundled;
            throw new FileNotFoundException("Keep sentient1.exe beside sentient1-Desktop.exe.");
        }
    }

    internal static async Task<string> CaptureAsync(params string[] arguments) => await CaptureInputAsync(null, arguments).ConfigureAwait(false);

    internal static async Task<string> CaptureInputAsync(string? input, params string[] arguments)
    {
        using var process = Start(arguments, input is not null);
        var output = process.StandardOutput.ReadToEndAsync();
        var errors = process.StandardError.ReadToEndAsync();
        if (input is not null) { await process.StandardInput.WriteAsync(input).ConfigureAwait(false); process.StandardInput.Close(); }
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try { await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false); }
        catch (OperationCanceledException)
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync().ConfigureAwait(false);
            throw new TimeoutException("The read-only monitor command timed out.");
        }
        var text = await output.ConfigureAwait(false);
        var error = await errors.ConfigureAwait(false);
        if (process.ExitCode != 0) throw new InvalidOperationException((text + "\n" + error).Trim());
        return text;
    }

    private static Process Start(IEnumerable<string> arguments, bool input)
    {
        var start = new ProcessStartInfo(Executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = input,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = AppContext.BaseDirectory
        };
        start.Environment["NO_COLOR"] = "1";
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        return Process.Start(start) ?? throw new InvalidOperationException("Could not start the monitor command.");
    }

    // The elevated helper accepts an operation, never a shell command or executable path.
    internal static string[] Arguments(EngineRequest request)
    {
        if (request.Setup is not null && request.Operation != "apply") throw new InvalidOperationException("Unexpected setup payload.");
        if (request.Operation is "resume" or "trust" or "kill")
        {
            var id = request.AlertId;
            if (string.IsNullOrWhiteSpace(id) || id.Length > 128 || id.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-' && c != '_'))
                throw new InvalidOperationException("Select a valid detection first.");
            return [request.Operation, id];
        }
        if (request.AlertId is not null) throw new InvalidOperationException("Unexpected alert identifier.");
        return request.Operation switch
        {
            "doctor" => ["doctor"],
            "repair" => ["doctor", "--fix"],
            "test" => ["test"],
            "release" => ["release"],
            "uninstall" => ["uninstall", "--yes"],
            "apply" when request.Setup is not null && Encoding.UTF8.GetByteCount(request.Setup) <= 65536 => ["desktop", "apply"],
            _ => throw new InvalidOperationException("Unsupported desktop operation.")
        };
    }

    internal static async Task RunAsync(EngineRequest request, Action<string> output)
    {
        _ = Arguments(request);
        var pipeName = "sentient1-" + Guid.NewGuid().ToString("N");
        using var identity = WindowsIdentity.GetCurrent();
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new PipeAccessRule(identity.User ?? throw new InvalidOperationException("No Windows user identity."), PipeAccessRights.FullControl, AccessControlType.Allow));
        // Explicit account ACL permits the same user's elevated token. CurrentUserOnly
        // also tests elevation level and would reject the UAC helper.
        using var pipe = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096, security);
        var start = new ProcessStartInfo(Environment.ProcessPath ?? throw new InvalidOperationException("Cannot locate the desktop application."))
        {
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = AppContext.BaseDirectory
        };
        start.ArgumentList.Add("--worker"); start.ArgumentList.Add(pipeName); start.ArgumentList.Add(Environment.ProcessId.ToString());
        using var worker = Process.Start(start) ?? throw new InvalidOperationException("Administrator helper did not start.");
        using var connectTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        await pipe.WaitForConnectionAsync(connectTimeout.Token).ConfigureAwait(false);
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var client) || client != worker.Id)
            throw new InvalidOperationException("The administrator connection could not be verified.");
        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, true);
        using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, true) { AutoFlush = true };
        await writer.WriteLineAsync(JsonSerializer.Serialize(request)).ConfigureAwait(false);
        while (await reader.ReadLineAsync().ConfigureAwait(false) is { } line)
        {
            var message = JsonSerializer.Deserialize<EngineMessage>(line) ?? throw new IOException("Invalid helper response.");
            if (message.Kind == "result")
            {
                if (message.ExitCode != 0) throw new InvalidOperationException(message.Text);
                return;
            }
            output(message.Text);
        }
        throw new IOException("The administrator helper disconnected before returning a result. Refresh status before retrying.");
    }

    internal static async Task<int> WorkerAsync(string pipeName, int parent)
    {
        if (!pipeName.StartsWith("sentient1-", StringComparison.Ordinal) || !Guid.TryParseExact(pipeName[10..], "N", out _)) return 2;
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) return 2;
        using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(30000).ConfigureAwait(false);
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var server) || server != parent) return 2;
        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, true);
        using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, true) { AutoFlush = true };
        using var writeLock = new SemaphoreSlim(1, 1);
        async Task Send(EngineMessage message)
        {
            await writeLock.WaitAsync().ConfigureAwait(false);
            try { await writer.WriteLineAsync(JsonSerializer.Serialize(message)).ConfigureAwait(false); }
            catch (IOException) { /* Finish the engine operation even if the dashboard disconnects. */ }
            finally { writeLock.Release(); }
        }
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            // Bounded one-line request; JSON escapes embedded setup newlines.
            var buffer = new char[1]; var requestText = new StringBuilder();
            while (await reader.ReadAsync(buffer.AsMemory(), timeout.Token).ConfigureAwait(false) != 0)
            {
                if (buffer[0] == '\n') break;
                if (requestText.Length >= 131072) throw new IOException("Desktop request too large.");
                requestText.Append(buffer[0]);
            }
            var request = JsonSerializer.Deserialize<EngineRequest>(requestText.ToString()) ?? throw new IOException("Missing desktop request.");
            using var process = Start(Arguments(request), request.Setup is not null);
            async Task Pump(StreamReader stream)
            {
                while (await stream.ReadLineAsync().ConfigureAwait(false) is { } line) await Send(new EngineMessage("output", line)).ConfigureAwait(false);
            }
            var stdout = Pump(process.StandardOutput); var stderr = Pump(process.StandardError);
            if (request.Setup is not null) { await process.StandardInput.WriteAsync(request.Setup).ConfigureAwait(false); process.StandardInput.Close(); }
            await Task.WhenAll(stdout, stderr, process.WaitForExitAsync()).ConfigureAwait(false);
            await Send(new EngineMessage("result", process.ExitCode == 0 ? "Completed." : $"The operation returned exit code {process.ExitCode}. Review the terminal output.", process.ExitCode)).ConfigureAwait(false);
            return process.ExitCode;
        }
        catch (Exception ex)
        {
            await Send(new EngineMessage("result", ex.Message, 1)).ConfigureAwait(false);
            return 1;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
}
