namespace AcronisBackupTrigger;

public enum TokenResult
{
    Authenticated,
    AuthenticationFailed,
    ConnectivityFailed,
    InvalidDataCenterUrl,
    AcronisUnavailable,
    UnexpectedResponse,
}

public interface IAcronisTransport
{
    Task<TokenResult> RequestTokenAsync(TriggerConfiguration configuration, CancellationToken cancellationToken);

    Task<DiscoveryResult<AcronisPolicy>> ListProtectionPoliciesAsync(
        TriggerConfiguration configuration,
        CancellationToken cancellationToken);

    Task<DiscoveryResult<AcronisResource>> ListResourcesAsync(
        TriggerConfiguration configuration,
        string policyId,
        CancellationToken cancellationToken);
}

public enum DiagnosticOutcome
{
    Authenticated,
    AuthenticationFailed,
    ConnectivityFailed,
    InvalidDataCenterUrl,
    AcronisUnavailable,
    UnexpectedResponse,
}

public sealed record DiagnosticResult(DiagnosticOutcome Outcome);

public sealed class Diagnostics(IAcronisTransport transport)
{
    public async Task<DiagnosticResult> CheckAsync(TriggerConfiguration configuration, CancellationToken cancellationToken = default)
    {
        var tokenResult = await transport.RequestTokenAsync(configuration, cancellationToken);
        return new DiagnosticResult(tokenResult switch
        {
            TokenResult.Authenticated => DiagnosticOutcome.Authenticated,
            TokenResult.AuthenticationFailed => DiagnosticOutcome.AuthenticationFailed,
            TokenResult.InvalidDataCenterUrl => DiagnosticOutcome.InvalidDataCenterUrl,
            TokenResult.AcronisUnavailable => DiagnosticOutcome.AcronisUnavailable,
            TokenResult.UnexpectedResponse => DiagnosticOutcome.UnexpectedResponse,
            _ => DiagnosticOutcome.ConnectivityFailed,
        });
    }
}
