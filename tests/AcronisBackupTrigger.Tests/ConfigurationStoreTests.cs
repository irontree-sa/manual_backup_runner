using AcronisBackupTrigger;

namespace AcronisBackupTrigger.Tests;

public sealed class ConfigurationStoreTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));

    [Fact]
    public void Save_then_load_returns_configuration_without_plaintext_secret()
    {
        var store = new ConfigurationStore(directory, new ReversingProtector());
        var expected = new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "client-secret");

        store.Save(expected);

        Assert.Equal(expected, store.Load());
        Assert.DoesNotContain("client-secret", File.ReadAllText(Path.Combine(directory, "configuration.dat")));
    }

    [Fact]
    public void Reset_removes_saved_configuration()
    {
        var store = new ConfigurationStore(directory, new ReversingProtector());
        store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "client-secret"));

        store.Reset();

        Assert.Null(store.Load());
    }

    public void Dispose()
    {
        if (Directory.Exists(directory))
            Directory.Delete(directory, recursive: true);
    }

    private sealed class ReversingProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => plaintext.Reverse().ToArray();
        public byte[] Unprotect(byte[] ciphertext) => ciphertext.Reverse().ToArray();
    }
}

public sealed class DiagnosticsTests
{
    private static readonly TriggerConfiguration Config = new("https://eu2.acronis.cloud", "client", "secret");

    [Theory]
    [InlineData(TokenResult.Authenticated, DiagnosticOutcome.Authenticated)]
    [InlineData(TokenResult.AuthenticationFailed, DiagnosticOutcome.AuthenticationFailed)]
    [InlineData(TokenResult.ConnectivityFailed, DiagnosticOutcome.ConnectivityFailed)]
    [InlineData(TokenResult.InvalidDataCenterUrl, DiagnosticOutcome.InvalidDataCenterUrl)]
    [InlineData(TokenResult.AcronisUnavailable, DiagnosticOutcome.AcronisUnavailable)]
    [InlineData(TokenResult.UnexpectedResponse, DiagnosticOutcome.UnexpectedResponse)]
    public async Task Diagnose_reports_each_transport_outcome_distinctly(TokenResult transportResult, DiagnosticOutcome expected)
    {
        var result = await new Diagnostics(new FakeAcronisTransport(transportResult)).CheckAsync(Config);

        Assert.Equal(expected, result.Outcome);
    }
}
