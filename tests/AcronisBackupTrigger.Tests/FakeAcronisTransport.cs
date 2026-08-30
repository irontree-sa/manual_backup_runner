using AcronisBackupTrigger;

namespace AcronisBackupTrigger.Tests;

/// <summary>
/// Deterministic Acronis transport double. No test using it contacts Acronis.
/// </summary>
public sealed class FakeAcronisTransport(TokenResult tokenResult = TokenResult.Authenticated) : IAcronisTransport
{
    public DiscoveryResult<AcronisPolicy> Policies { get; init; } = new(DiscoveryStatus.Succeeded, []);
    public DiscoveryResult<AcronisResource> Resources { get; init; } = new(DiscoveryStatus.Succeeded, []);
    public List<string> RequestedPolicyIds { get; } = [];

    public Task<TokenResult> RequestTokenAsync(TriggerConfiguration configuration, CancellationToken cancellationToken) =>
        Task.FromResult(tokenResult);

    public Task<DiscoveryResult<AcronisPolicy>> ListProtectionPoliciesAsync(
        TriggerConfiguration configuration,
        CancellationToken cancellationToken) =>
        Task.FromResult(Policies);

    public Task<DiscoveryResult<AcronisResource>> ListResourcesAsync(
        TriggerConfiguration configuration,
        string policyId,
        CancellationToken cancellationToken)
    {
        RequestedPolicyIds.Add(policyId);
        return Task.FromResult(Resources);
    }

    public ExecutionState State { get; init; } = ExecutionState.Idle;
    public StartOutcome Start { get; init; } = StartOutcome.Accepted;
    public int StateReadCount { get; private set; }

    public Task<ExecutionState> GetExecutionStateAsync(
        TriggerConfiguration configuration,
        ConfiguredTarget target,
        CancellationToken cancellationToken)
    {
        StateReadCount++;
        return Task.FromResult(State);
    }

    public Task<StartOutcome> StartPolicyAsync(
        TriggerConfiguration configuration,
        ConfiguredTarget target,
        CancellationToken cancellationToken,
        Action? onSend = null,
        Action? onPreSendFailure = null)
    {
        StartCount++;
        return Task.FromResult(Start);
    }
}
