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

    Task<ExecutionState> GetExecutionStateAsync(
        TriggerConfiguration configuration,
        string policyId,
        string resourceId,
        CancellationToken cancellationToken);

    Task<StartOutcome> StartPolicyAsync(
        TriggerConfiguration configuration,
        string policyId,
        string resourceId,
        CancellationToken cancellationToken,
        Action? onSend = null,
        Action? onPreSendFailure = null);
}

public enum DiagnosticOutcome
{
    Authenticated,
    AuthenticationFailed,
    ConnectivityFailed,
    InvalidDataCenterUrl,
    AcronisUnavailable,
    UnexpectedResponse,
    TargetIdle,
    TargetRunning,
    TargetAuthenticationFailed,
    TargetConnectivityFailed,
    TargetRejected,
    TargetUnexpectedResponse,
}

public sealed record DiagnosticResult(DiagnosticOutcome Outcome);

public sealed class Diagnostics(IAcronisTransport transport)
{
    public async Task<DiagnosticResult> CheckAsync(TriggerConfiguration configuration, CancellationToken cancellationToken = default)
    {
        var tokenResult = await transport.RequestTokenAsync(configuration, cancellationToken);
        if (tokenResult != TokenResult.Authenticated)
        {
            return new DiagnosticResult(tokenResult switch
            {
                TokenResult.AuthenticationFailed => DiagnosticOutcome.AuthenticationFailed,
                TokenResult.InvalidDataCenterUrl => DiagnosticOutcome.InvalidDataCenterUrl,
                TokenResult.AcronisUnavailable => DiagnosticOutcome.AcronisUnavailable,
                TokenResult.UnexpectedResponse => DiagnosticOutcome.UnexpectedResponse,
                _ => DiagnosticOutcome.ConnectivityFailed,
            });
        }

        // Authentication alone is not a complete diagnostic: verify the selected
        // policy/resource is still valid and readable through the status path.
        if (configuration.PolicyId is not { Length: > 0 } policyId
            || configuration.ResourceId is not { Length: > 0 } resourceId)
        {
            return new DiagnosticResult(DiagnosticOutcome.Authenticated);
        }

        var state = await transport.GetExecutionStateAsync(configuration, policyId, resourceId, cancellationToken);
        return new DiagnosticResult(state switch
        {
            ExecutionState.Idle => DiagnosticOutcome.TargetIdle,
            ExecutionState.Running => DiagnosticOutcome.TargetRunning,
            ExecutionState.AuthenticationFailed => DiagnosticOutcome.TargetAuthenticationFailed,
            ExecutionState.ConnectivityFailed => DiagnosticOutcome.TargetConnectivityFailed,
            ExecutionState.AcronisRejected => DiagnosticOutcome.TargetRejected,
            ExecutionState.UnexpectedResponse => DiagnosticOutcome.TargetUnexpectedResponse,
            _ => DiagnosticOutcome.TargetUnexpectedResponse,
        });
    }
}
