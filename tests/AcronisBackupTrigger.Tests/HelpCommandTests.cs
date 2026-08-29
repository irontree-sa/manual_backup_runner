using System.Diagnostics;
using AcronisBackupTrigger;

namespace AcronisBackupTrigger.Tests;

public sealed class HelpCommandTests
{
    [Fact]
    public async Task Help_writes_exact_static_guide_without_touching_configuration()
    {
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        var protector = new RecordingProtector();
        var store = new ConfigurationStore(directory, protector);
        store.Save(new TriggerConfiguration(
            "https://tenant.example",
            "client-id-sentinel",
            "client-secret-sentinel",
            "policy-id-sentinel",
            "policy-name-sentinel",
            "resource-id-123",
            "resource-name-sentinel"));

        var output = new StringWriter();
        var error = new StringWriter();
        var host = new CommandHost(
            store,
            () => throw new InvalidOperationException("help must not construct transport"),
            new StringReader(""),
            output,
            error,
            () => throw new InvalidOperationException("help must not read secret"));

        var exit = await host.RunAsync(["help"]);

        Assert.Equal(ExitCodes.Success, exit);
        Assert.Equal(HelpContent.Text + Environment.NewLine, output.ToString());
        Assert.Empty(error.ToString());
        Assert.Equal(0, protector.UnprotectCalls);
        Assert.DoesNotContain("https://tenant.example", output.ToString());
        Assert.DoesNotContain("client-secret-sentinel", output.ToString());
        Assert.DoesNotContain("resource-id-123", output.ToString());

        var guide = output.ToString();

        // No-argument invocation.
        Assert.Contains("AcronisBackupTrigger.exe", guide);

        // Every command is documented.
        Assert.Contains("setup", guide);
        Assert.Contains("select-target", guide);
        Assert.Contains("list-policies", guide);
        Assert.Contains("list-resources", guide);
        Assert.Contains("diagnose", guide);
        Assert.Contains("clear-pending", guide);
        Assert.Contains("reset", guide);

        // Exit-code guidance.
        Assert.Contains("Exit 12", guide);
        Assert.Contains("Exit 14", guide);
        Assert.Contains("Exit 18", guide);
        Assert.Contains("Exit 19", guide);

        // Acronis console rules.
        Assert.Contains("Acronis console", guide);

        // Identity/elevation distinction.
        Assert.Contains("Configuration administrator identity", guide);
        Assert.Contains("elevated Administrator", guide);

        // Release verification.
        Assert.Contains("SHA256SUMS.txt", guide);
        Assert.Contains("Get-FileHash", guide);
        Assert.Contains("Unblock-File", guide);
        Assert.Contains("allow-list", guide);

        // Configuration and log locations.
        Assert.Contains(@"C:\ProgramData\AcronisBackupTrigger", guide);
        Assert.Contains("trigger.log", guide);
    }

    [Fact]
    public async Task Help_never_evaluates_administrator_gate()
    {
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        var protector = new RecordingProtector();
        var store = new ConfigurationStore(directory, protector);

        var output = new StringWriter();
        var error = new StringWriter();
        var host = new CommandHost(
            store,
            () => throw new InvalidOperationException("help must not construct transport"),
            new StringReader(""),
            output,
            error,
            () => throw new InvalidOperationException("help must not read secret"),
            administratorGate: new ThrowingAdministratorGate());

        var exit = await host.RunAsync(["help"]);

        Assert.Equal(ExitCodes.Success, exit);
        Assert.Equal(HelpContent.Text + Environment.NewLine, output.ToString());
        Assert.Empty(error.ToString());
        Assert.Equal(0, protector.UnprotectCalls);
    }
    [Fact]
    public async Task Executable_help_is_cross_platform_and_exits_zero()
    {
        var result = await ExecuteApplicationAsync("help");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Acronis Backup Trigger", result.StandardOutput);
        Assert.Equal("", result.StandardError);
    }

    private static async Task<(int ExitCode, string StandardOutput, string StandardError)> ExecuteApplicationAsync(string argument)
    {
        var start = new ProcessStartInfo
        {
            FileName = "dotnet",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        start.ArgumentList.Add(ExecutablePath);
        start.ArgumentList.Add(argument);

        using var process = Process.Start(start)!;
        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();

        return (process.ExitCode, stdout, stderr);
    }

    private static string ExecutablePath =>
        Path.Combine(AppContext.BaseDirectory, "AcronisBackupTrigger.dll");

    private sealed class RecordingProtector : ISecretProtector
    {
        public int UnprotectCalls { get; private set; }

        public byte[] Protect(byte[] plaintext) => plaintext.Reverse().ToArray();

        public byte[] Unprotect(byte[] ciphertext)
        {
            UnprotectCalls++;
            throw new InvalidOperationException("help must not load configuration");
        }
    }

    private sealed class ThrowingAdministratorGate : IAdministratorGate
    {
        public bool IsElevated => throw new InvalidOperationException("help must not evaluate the administrator gate");
    }
}
