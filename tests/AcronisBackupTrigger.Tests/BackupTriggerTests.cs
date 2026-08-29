using AcronisBackupTrigger;

namespace AcronisBackupTrigger.Tests;

public sealed class BackupTriggerTests
{
    private static readonly TriggerConfiguration Configured = new(
        "https://eu2.acronis.cloud", "client-id", "secret",
        "policy-1", "Windows Backup", "resource-1", "SERVER-01");

    [Fact]
    public async Task Run_succeeds_only_once_the_policy_is_observed_running()
    {
        var transport = new ScriptedTransport
        {
            States = [ExecutionState.Idle, ExecutionState.Idle, ExecutionState.Running],
            Start = StartOutcome.Accepted,
        };
        var delays = new List<TimeSpan>();

        var result = await Trigger(transport, delays).RunAsync(Configured, CancellationToken.None);

        Assert.Equal(TriggerOutcome.ObservedRunning, result.Outcome);
        Assert.Equal(1, transport.StartCount);
        Assert.NotEmpty(delays);
    }
    [Fact]
    public async Task Run_reports_a_synchronously_completed_start_without_polling()
    {
        var transport = new ScriptedTransport
        {
            States = [ExecutionState.Idle],
            Start = StartOutcome.CompletedSynchronously,
        };
        var delays = new List<TimeSpan>();
        var pending = new RecordingPendingStore();

        var result = await Trigger(transport, delays, pending: pending).RunAsync(Configured, CancellationToken.None);

        Assert.Equal(TriggerOutcome.CompletedSynchronously, result.Outcome);
        Assert.Empty(delays);
        Assert.Null(pending.Marked);
    }

    [Fact]
    public async Task Run_refuses_to_start_a_policy_that_is_already_running()
    {
        var transport = new ScriptedTransport { States = [ExecutionState.Running] };

        var result = await Trigger(transport).RunAsync(Configured, CancellationToken.None);

        Assert.Equal(TriggerOutcome.AlreadyRunning, result.Outcome);
        Assert.Equal(0, transport.StartCount);
    }

    [Fact]
    public async Task Run_reports_acceptance_without_observation_when_the_window_elapses()
    {
        var transport = new ScriptedTransport { States = [ExecutionState.Idle], Start = StartOutcome.Accepted };
        var delays = new List<TimeSpan>();

        var result = await Trigger(transport, delays, observationWindow: TimeSpan.FromSeconds(6)).RunAsync(Configured, CancellationToken.None);

        Assert.Equal(TriggerOutcome.AcceptedNotObserved, result.Outcome);
        Assert.Equal(1, transport.StartCount);
        Assert.Equal(TimeSpan.FromSeconds(6), delays.Aggregate(TimeSpan.Zero, (total, next) => total + next));
    }

    [Fact]
    public async Task Run_never_resends_a_start_request_whose_outcome_is_unknown()
    {
        var transport = new ScriptedTransport { States = [ExecutionState.Idle], Start = StartOutcome.OutcomeUnknown };

        var result = await Trigger(transport).RunAsync(Configured, CancellationToken.None);

        Assert.Equal(TriggerOutcome.OutcomeUnknown, result.Outcome);
        Assert.Equal(1, transport.StartCount);
    }

    [Theory]
    [InlineData(StartOutcome.Rejected, TriggerOutcome.AcronisRejected)]
    [InlineData(StartOutcome.AuthenticationFailed, TriggerOutcome.AuthenticationFailed)]
    [InlineData(StartOutcome.NotSent, TriggerOutcome.ConnectivityFailed)]
    public async Task Run_maps_start_failures_to_distinct_outcomes(StartOutcome start, TriggerOutcome expected)
    {
        var transport = new ScriptedTransport { States = [ExecutionState.Idle], Start = start };

        var result = await Trigger(transport).RunAsync(Configured, CancellationToken.None);

        Assert.Equal(expected, result.Outcome);
    }

    [Fact]
    public async Task Run_reports_a_state_check_failure_without_starting_a_backup()
    {
        var transport = new ScriptedTransport { States = [ExecutionState.ConnectivityFailed] };

        var result = await Trigger(transport).RunAsync(Configured, CancellationToken.None);

        Assert.Equal(TriggerOutcome.ConnectivityFailed, result.Outcome);
        Assert.Equal(0, transport.StartCount);
    }

    [Theory]
    [InlineData(null, "resource-1")]
    [InlineData("policy-1", null)]
    public async Task Run_requires_a_configured_policy_and_resource(string? policyId, string? resourceId)
    {
        var transport = new ScriptedTransport { States = [ExecutionState.Idle] };
        var configuration = Configured with { PolicyId = policyId, ResourceId = resourceId };

        var result = await Trigger(transport).RunAsync(configuration, CancellationToken.None);

        Assert.Equal(TriggerOutcome.TargetNotConfigured, result.Outcome);
        Assert.Equal(0, transport.StartCount);
    }

    [Fact]
    public async Task Run_sends_the_configured_policy_and_resource()
    {
        var transport = new ScriptedTransport { States = [ExecutionState.Idle, ExecutionState.Running], Start = StartOutcome.Accepted };

        await Trigger(transport).RunAsync(Configured, CancellationToken.None);

        Assert.Equal([("policy-1", "resource-1")], transport.StartedTargets);
    }

    [Fact]
    public async Task Run_refuses_when_a_previous_start_outcome_is_still_unknown()
    {
        var pending = new RecordingPendingStore { Marked = DateTimeOffset.UtcNow.AddMinutes(-5) };
        var transport = new ScriptedTransport { States = [ExecutionState.Idle] };

        var result = await Trigger(transport, pending: pending).RunAsync(Configured, CancellationToken.None);

        Assert.Equal(TriggerOutcome.StartOutstanding, result.Outcome);
        Assert.Equal(0, transport.StartCount);
    }

    [Fact]
    public async Task An_unknown_start_outcome_is_recorded_so_a_later_run_cannot_resend_it()
    {
        var pending = new RecordingPendingStore();
        var transport = new ScriptedTransport { States = [ExecutionState.Idle], Start = StartOutcome.OutcomeUnknown };

        var result = await Trigger(transport, pending: pending).RunAsync(Configured, CancellationToken.None);

        Assert.Equal(TriggerOutcome.OutcomeUnknown, result.Outcome);
        Assert.NotNull(pending.Marked);
    }

    [Fact]
    public async Task An_observed_start_clears_the_outstanding_marker()
    {
        var pending = new RecordingPendingStore();
        var transport = new ScriptedTransport { States = [ExecutionState.Idle, ExecutionState.Running], Start = StartOutcome.Accepted };

        var result = await Trigger(transport, pending: pending).RunAsync(Configured, CancellationToken.None);

        Assert.Equal(TriggerOutcome.ObservedRunning, result.Outcome);
        Assert.Null(pending.Marked);
    }

    [Fact]
    public async Task A_rejected_start_clears_the_outstanding_marker()
    {
        var pending = new RecordingPendingStore();
        var transport = new ScriptedTransport { States = [ExecutionState.Idle], Start = StartOutcome.Rejected };

        await Trigger(transport, pending: pending).RunAsync(Configured, CancellationToken.None);

        Assert.Null(pending.Marked);
    }

    [Fact]
    public async Task An_accepted_but_unobserved_start_keeps_the_outstanding_marker()
    {
        var pending = new RecordingPendingStore();
        var transport = new ScriptedTransport { States = [ExecutionState.Idle], Start = StartOutcome.Accepted };

        var result = await Trigger(transport, pending: pending, observationWindow: TimeSpan.FromSeconds(6))
            .RunAsync(Configured, CancellationToken.None);

        Assert.Equal(TriggerOutcome.AcceptedNotObserved, result.Outcome);
        Assert.NotNull(pending.Marked);
    }

    private sealed class RecordingPendingStore : IPendingStartStore
    {
        public DateTimeOffset? Marked { get; set; }

        public DateTimeOffset? Read() => Marked;
        public void Mark(DateTimeOffset sentAt) => Marked = sentAt;
        public void Clear() => Marked = null;
    }

    private static BackupTrigger Trigger(
        ScriptedTransport transport,
        List<TimeSpan>? delays = null,
        TimeSpan? observationWindow = null,
        IPendingStartStore? pending = null)
    {
        var elapsed = TimeSpan.Zero;
        return new BackupTrigger(
            transport,
            pending ?? new NullPendingStartStore(),
            (duration, _) =>
            {
                delays?.Add(duration);
                elapsed += duration;
                return Task.CompletedTask;
            },
            observationWindow ?? TimeSpan.FromSeconds(30),
            () => elapsed);
    }
    private sealed class ScriptedTransport : IAcronisTransport
    {
        private int stateReads;

        public ExecutionState[] States { get; init; } = [ExecutionState.Idle];
        public StartOutcome Start { get; init; } = StartOutcome.Accepted;
        public int StartCount { get; private set; }
        public List<(string PolicyId, string ResourceId)> StartedTargets { get; } = [];

        public Task<TokenResult> RequestTokenAsync(TriggerConfiguration configuration, CancellationToken cancellationToken) =>
            Task.FromResult(TokenResult.Authenticated);

        public Task<DiscoveryResult<AcronisPolicy>> ListProtectionPoliciesAsync(TriggerConfiguration configuration, CancellationToken cancellationToken) =>
            Task.FromResult(new DiscoveryResult<AcronisPolicy>(DiscoveryStatus.Succeeded, []));

        public Task<DiscoveryResult<AcronisResource>> ListResourcesAsync(TriggerConfiguration configuration, string policyId, CancellationToken cancellationToken) =>
            Task.FromResult(new DiscoveryResult<AcronisResource>(DiscoveryStatus.Succeeded, []));

        public Task<ExecutionState> GetExecutionStateAsync(
            TriggerConfiguration configuration,
            string policyId,
            string resourceId,
            CancellationToken cancellationToken)
        {
            var state = States[Math.Min(stateReads, States.Length - 1)];
            stateReads++;
            return Task.FromResult(state);
        }

        public Task<StartOutcome> StartPolicyAsync(
            TriggerConfiguration configuration,
            string policyId,
            string resourceId,
            CancellationToken cancellationToken)
        {
            StartCount++;
            StartedTargets.Add((policyId, resourceId));
            return Task.FromResult(Start);
        }
    }
}
