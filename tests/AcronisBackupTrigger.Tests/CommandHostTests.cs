using AcronisBackupTrigger;

namespace AcronisBackupTrigger.Tests;

public sealed class CommandHostTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
    private readonly StringWriter output = new();
    private readonly StringWriter error = new();

    [Fact]
    public async Task No_arguments_on_an_unconfigured_machine_reports_missing_configuration()
    {
        var exit = await Host([], Store()).RunAsync([]);

        Assert.Equal(ExitCodes.ConfigurationMissing, exit);
        Assert.Contains("Configuration is missing", error.ToString());
    }

    [Fact]
    public async Task Setup_saves_configuration_and_never_echoes_the_secret()
    {
        var store = Store();

        var exit = await Host(["https://eu2.acronis.cloud", "client-id", "1", "1"], store).RunAsync(["setup"]);

        Assert.Equal(ExitCodes.Success, exit);
        Assert.Equal(
            new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "typed-secret", "policy-1", "Daily", "resource-1", "SERVER-01"),
            store.Load());
        Assert.DoesNotContain("typed-secret", output.ToString());
        Assert.DoesNotContain("typed-secret", error.ToString());
    }

    [Fact]
    public async Task Setup_keeps_existing_configuration_unless_replacement_is_confirmed()
    {
        var store = Store();
        var original = new TriggerConfiguration("https://eu2.acronis.cloud", "original-id", "original-secret");
        store.Save(original);

        var exit = await Host(["no"], store).RunAsync(["setup"]);

        Assert.Equal(ExitCodes.Success, exit);
        Assert.Equal(original, store.Load());
        Assert.Contains("original-id", output.ToString());
        Assert.DoesNotContain("original-secret", output.ToString());
    }

    [Fact]
    public async Task Setup_replaces_existing_configuration_when_confirmed()
    {
        var store = Store();
        store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "original-id", "original-secret"));

        var exit = await Host(["REPLACE", "https://us5.acronis.cloud", "new-id", "1", "1"], store).RunAsync(["setup"]);

        Assert.Equal(ExitCodes.Success, exit);
        Assert.Equal(
            new TriggerConfiguration("https://us5.acronis.cloud", "new-id", "typed-secret", "policy-1", "Daily", "resource-1", "SERVER-01"),
            store.Load());
    }

    [Fact]
    public async Task Reset_removes_configuration_and_advises_revocation()
    {
        var store = Store();
        store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "secret"));

        var exit = await Host([], store).RunAsync(["reset"]);

        Assert.Equal(ExitCodes.Success, exit);
        Assert.Null(store.Load());
        Assert.Contains("Revoke", output.ToString());
    }

    [Fact]
    public async Task Diagnose_reports_missing_configuration()
    {
        var exit = await Host([], Store()).RunAsync(["diagnose"]);

        Assert.Equal(ExitCodes.ConfigurationMissing, exit);
        Assert.Contains("Configuration is missing", error.ToString());
    }

    [Theory]
    [InlineData(TokenResult.Authenticated, ExitCodes.Success)]
    [InlineData(TokenResult.AuthenticationFailed, ExitCodes.DiagnosticsFailed)]
    [InlineData(TokenResult.InvalidDataCenterUrl, ExitCodes.DiagnosticsFailed)]
    public async Task Diagnose_translates_transport_outcome_to_exit_code(TokenResult transportResult, int expectedExit)
    {
        var store = Store();
        store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "secret"));

        var exit = await Host([], store, transportResult).RunAsync(["diagnose"]);

        Assert.Equal(expectedExit, exit);
        Assert.Contains(transportResult.ToString(), output.ToString());
    }

    [Fact]
    public async Task Diagnose_reports_inaccessible_configuration_distinctly_from_missing_configuration()
    {
        var host = Host([], new ConfigurationStore(directory, new DeniedProtector()));
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Path.Combine(directory, "configuration.dat"), [1, 2, 3]);

        var exit = await host.RunAsync(["diagnose"]);

        Assert.Equal(ExitCodes.ConfigurationInaccessible, exit);
        Assert.Contains("not accessible", error.ToString());
    }

    [Fact]
    public async Task Diagnose_reports_undecryptable_configuration_distinctly()
    {
        var host = Host([], new ConfigurationStore(directory, new CorruptProtector()));
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Path.Combine(directory, "configuration.dat"), [1, 2, 3]);

        var exit = await host.RunAsync(["diagnose"]);

        Assert.Equal(ExitCodes.ConfigurationUnreadable, exit);
        Assert.Contains("Run setup", error.ToString());
    }
    [Theory]
    [InlineData("setup")]
    [InlineData("reset")]
    [InlineData("select-target")]
    [InlineData("clear-pending")]
    public async Task State_changing_commands_require_an_elevated_administrator(string command)
    {
        var store = new ConfigurationStore(directory, new DeniedProtector());
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Path.Combine(directory, "configuration.dat"), [1, 2, 3]);

        var host = new CommandHost(
            store,
            () => throw new InvalidOperationException("transport must not be constructed"),
            new StringReader(""),
            output,
            error,
            () => throw new InvalidOperationException("secret must not be read"),
            administratorGate: new DeniedAdministratorGate());

        var exit = await host.RunAsync([command]);

        Assert.Equal(ExitCodes.AdministratorRequired, exit);
        Assert.Contains("elevated Administrator", error.ToString());
    }

    private sealed class DeniedAdministratorGate : IAdministratorGate
    {
        public bool IsElevated => false;
    }

    private ConfigurationStore Store() => new(directory, new ReversingProtector());

    private CommandHost Host(string[] lines, ConfigurationStore store, TokenResult transportResult = TokenResult.Authenticated) =>
        new(store,
            () => new FakeAcronisTransport(transportResult)
            {
                Policies = new(DiscoveryStatus.Succeeded, [new AcronisPolicy("policy-1", "Daily")]),
                Resources = new(DiscoveryStatus.Succeeded, [new AcronisResource("resource-1", "SERVER-01")]),
            },
            new StringReader(string.Join(Environment.NewLine, lines)),
            output,
            error,
            () => "typed-secret");

    public void Dispose()
    {
        output.Dispose();
        error.Dispose();
        if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }



    private sealed class ReversingProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => plaintext.Reverse().ToArray();
        public byte[] Unprotect(byte[] ciphertext) => ciphertext.Reverse().ToArray();
    }

    private sealed class DeniedProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => plaintext;
        public byte[] Unprotect(byte[] ciphertext) => throw new UnauthorizedAccessException();
    }

    private sealed class CorruptProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => plaintext;
        public byte[] Unprotect(byte[] ciphertext) => throw new System.Security.Cryptography.CryptographicException();
    }
}
