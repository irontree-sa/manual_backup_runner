using AcronisBackupTrigger;

namespace AcronisBackupTrigger.Tests;

public sealed class HelpCommandTests
{
    [Fact]
    public async Task Help_writes_the_static_operator_guide_without_configuration()
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var host = new CommandHost(
            new ConfigurationStore(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")), new ReversingProtector()),
            () => throw new InvalidOperationException("help must not construct transport"),
            new StringReader(""), output, error, () => throw new InvalidOperationException("help must not read secret"));

        var exit = await host.RunAsync(["help"]);

        Assert.Equal(ExitCodes.Success, exit);
        Assert.Empty(error.ToString());
        Assert.Contains("AcronisBackupTrigger.exe", output.ToString());
        Assert.Contains("setup", output.ToString());
        Assert.Contains("select-target", output.ToString());
        Assert.Contains("list-policies", output.ToString());
        Assert.Contains("list-resources", output.ToString());
        Assert.Contains("diagnose", output.ToString());
        Assert.Contains("clear-pending", output.ToString());
        Assert.Contains("reset", output.ToString());
        Assert.Contains("Exit 12", output.ToString());
        Assert.Contains("Exit 14", output.ToString());
        Assert.Contains("Exit 18", output.ToString());
        Assert.Contains("Exit 19", output.ToString());
        Assert.Contains("Acronis console", output.ToString());
    }

    [Fact]
    public async Task Help_never_includes_mutable_configuration_or_secret_sentinels()
    {
        var output = new StringWriter();
        var host = CreateHelpHost(output, new StringWriter());

        await host.RunAsync(["help"]);

        var text = output.ToString();
        Assert.DoesNotContain("https://tenant.example", text);
        Assert.DoesNotContain("client-secret", text);
        Assert.DoesNotContain("resource-id-123", text);
        Assert.DoesNotContain("eyJhbGci", text);
    }

    [Fact]
    public async Task Help_documents_identity_and_elevation_distinction()
    {
        var output = new StringWriter();
        var host = CreateHelpHost(output, new StringWriter());

        await host.RunAsync(["help"]);

        var text = output.ToString();
        Assert.Contains("Administrator", text);
        Assert.Contains("elevated", text);
        Assert.Contains("Configuration administrator", text);
    }

    [Fact]
    public async Task Help_documents_release_verification_and_log_locations()
    {
        var output = new StringWriter();
        var host = CreateHelpHost(output, new StringWriter());

        await host.RunAsync(["help"]);

        var text = output.ToString();
        Assert.Contains("SHA256SUMS.txt", text);
        Assert.Contains("Get-FileHash", text);
        Assert.Contains("Unblock-File", text);
        Assert.Contains("allow-list", text);
        Assert.Contains(@"C:\ProgramData\AcronisBackupTrigger\trigger.log", text);
    }

    private static CommandHost CreateHelpHost(StringWriter output, StringWriter error) =>
        new(
            new ConfigurationStore(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")), new ReversingProtector()),
            () => throw new InvalidOperationException("help must not construct transport"),
            new StringReader(""), output, error, () => throw new InvalidOperationException("help must not read secret"));

    private sealed class ReversingProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => plaintext.Reverse().ToArray();
        public byte[] Unprotect(byte[] ciphertext) => ciphertext.Reverse().ToArray();
    }
}
