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
    }

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
}
