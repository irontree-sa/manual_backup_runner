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
    [Fact]
    public async Task Diagnose_returns_authenticated_when_transport_issues_token()
    {
        var diagnostics = new Diagnostics(new TokenTransport(TokenResult.Authenticated));

        var result = await diagnostics.CheckAsync(new TriggerConfiguration("https://eu2.acronis.cloud", "client", "secret"));

        Assert.Equal(DiagnosticOutcome.Authenticated, result.Outcome);
    }

    private sealed class TokenTransport(TokenResult result) : IAcronisTransport
    {
        public Task<TokenResult> RequestTokenAsync(TriggerConfiguration configuration, CancellationToken cancellationToken) =>
            Task.FromResult(result);
    }

    [Theory]
    [InlineData(TokenResult.AuthenticationFailed, DiagnosticOutcome.AuthenticationFailed)]
    [InlineData(TokenResult.ConnectivityFailed, DiagnosticOutcome.ConnectivityFailed)]
    public async Task Diagnose_maps_transport_failure(TokenResult transportResult, DiagnosticOutcome expected)
    {
        var result = await new Diagnostics(new TokenTransport(transportResult))
            .CheckAsync(new TriggerConfiguration("https://eu2.acronis.cloud", "client", "secret"));

        Assert.Equal(expected, result.Outcome);
    }
}
