using AcronisBackupTrigger;

namespace AcronisBackupTrigger.Tests;

public sealed class BackupTriggerTests
{
    private static readonly TriggerConfiguration Configured = new(
        "https://eu2.acronis.cloud", "client-id", "secret",
        new ConfiguredTarget("policy-1", "Windows Backup", "resource-1", "SERVER-01"));

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

    [Fact]
    public async Task Run_requires_a_configured_target()
    {
        var transport = new ScriptedTransport { States = [ExecutionState.Idle] };
        var configuration = Configured with { Target = null };

        var result = await Trigger(transport).RunAsync(configuration, CancellationToken.None);

        Assert.Equal(TriggerOutcome.TargetNotConfigured, result.Outcome);
        Assert.Equal(0, transport.StartCount);
    }

    [Theory]
    [InlineData("", "resource-1")]
    [InlineData("policy-1", "")]
    public async Task Run_requires_non_empty_execution_ids(string policyId, string resourceId)
    {
        var transport = new ScriptedTransport { States = [ExecutionState.Idle] };
        var configuration = Configured with
        {
            Target = new ConfiguredTarget(policyId, "Windows Backup", resourceId, "SERVER-01"),
        };

        var result = await Trigger(transport).RunAsync(configuration, CancellationToken.None);

        Assert.Equal(TriggerOutcome.TargetNotConfigured, result.Outcome);
        Assert.Equal(0, transport.StartCount);
        Assert.Equal(0, transport.StateReads);
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
    public async Task An_accepted_but_unobserved_start_does_not_block_later_runs()
    {
        var pending = new RecordingPendingStore();
        var transport = new ScriptedTransport { States = [ExecutionState.Idle], Start = StartOutcome.Accepted };

        var result = await Trigger(transport, pending: pending, observationWindow: TimeSpan.FromSeconds(6))
            .RunAsync(Configured, CancellationToken.None);

        Assert.Equal(TriggerOutcome.AcceptedNotObserved, result.Outcome);
        Assert.Null(pending.Marked);
    }

    [Fact]
    public async Task Run_reports_acceptance_when_a_status_call_crosses_the_observation_deadline()
    {
        // The status call itself consumes the window: it reports Running only after
        // the fixed deadline has already elapsed, so it must not count as success.
        var clock = new MutableClock();
        var transport = new DeadlineCrossingTransport(clock);
        var pending = new RecordingPendingStore();

        var trigger = new BackupTrigger(
            transport,
            pending,
            (duration, _) =>
            {
                clock.Advance(duration);
                return Task.CompletedTask;
            },
            TimeSpan.FromSeconds(6),
            () => clock.Elapsed);

        var result = await trigger.RunAsync(Configured, CancellationToken.None);

        Assert.Equal(TriggerOutcome.AcceptedNotObserved, result.Outcome);
        Assert.Equal(1, transport.StartCount);
        Assert.Null(pending.Marked);
    }
    [Fact]
    public async Task Cancellation_before_the_put_boundary_leaves_no_pending_marker()
    {
        // A transport that cancels during pre-send work (e.g. second token acquisition)
        // never invokes onSend, so no durable marker may be raised.
        var pending = new RecordingPendingStore();
        var transport = new PreSendCancellingTransport();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Trigger(transport, pending: pending).RunAsync(Configured, new CancellationToken(true)));

        Assert.Null(pending.Marked);
    }

    [Fact]
    public async Task Cancellation_after_the_put_boundary_retains_the_pending_marker()
    {
        // A transport that raises onSend then cancels (the PUT may have reached Acronis)
        // must leave the durable marker in place so a later run cannot resend.
        var pending = new RecordingPendingStore();
        var transport = new PostSendCancellingTransport();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Trigger(transport, pending: pending).RunAsync(Configured, new CancellationToken(true)));

        Assert.NotNull(pending.Marked);
    }

    [Fact]
    public async Task An_unexpected_start_response_maps_to_unexpected_response_and_clears_the_marker()
    {
        var pending = new RecordingPendingStore();
        var transport = new ScriptedTransport { States = [ExecutionState.Idle], Start = StartOutcome.UnexpectedResponse };

        var result = await Trigger(transport, pending: pending).RunAsync(Configured, CancellationToken.None);

        Assert.Equal(TriggerOutcome.UnexpectedResponse, result.Outcome);
        Assert.Null(pending.Marked);
    }

    [Fact]
    public async Task An_unexpected_start_response_after_send_retains_the_pending_marker()
    {
        var pending = new RecordingPendingStore();
        var transport = new ScriptedTransport { States = [ExecutionState.Idle], Start = StartOutcome.UnexpectedResponseAfterSend };

        var result = await Trigger(transport, pending: pending).RunAsync(Configured, CancellationToken.None);

        Assert.Equal(TriggerOutcome.UnexpectedResponse, result.Outcome);
        Assert.NotNull(pending.Marked);
    }

    private sealed class PreSendCancellingTransport : IAcronisTransport
    {
        public Task<TokenResult> RequestTokenAsync(TriggerConfiguration configuration, CancellationToken cancellationToken) =>
            Task.FromResult(TokenResult.Authenticated);
        public Task<DiscoveryResult<AcronisPolicy>> ListProtectionPoliciesAsync(TriggerConfiguration configuration, CancellationToken cancellationToken) =>
            Task.FromResult(new DiscoveryResult<AcronisPolicy>(DiscoveryStatus.Succeeded, []));
        public Task<DiscoveryResult<AcronisResource>> ListResourcesAsync(TriggerConfiguration configuration, string policyId, CancellationToken cancellationToken) =>
            Task.FromResult(new DiscoveryResult<AcronisResource>(DiscoveryStatus.Succeeded, []));
        public Task<ExecutionState> GetExecutionStateAsync(TriggerConfiguration configuration, ConfiguredTarget target, CancellationToken cancellationToken) =>
            Task.FromResult(ExecutionState.Idle);
        public Task<StartOutcome> StartPolicyAsync(TriggerConfiguration configuration, ConfiguredTarget target, CancellationToken cancellationToken, Action? onSend = null, Action? onPreSendFailure = null) =>
            throw new OperationCanceledException(cancellationToken);
    }
    private sealed class PostSendCancellingTransport : IAcronisTransport
    {
        public Task<TokenResult> RequestTokenAsync(TriggerConfiguration configuration, CancellationToken cancellationToken) =>
            Task.FromResult(TokenResult.Authenticated);
        public Task<DiscoveryResult<AcronisPolicy>> ListProtectionPoliciesAsync(TriggerConfiguration configuration, CancellationToken cancellationToken) =>
            Task.FromResult(new DiscoveryResult<AcronisPolicy>(DiscoveryStatus.Succeeded, []));
        public Task<DiscoveryResult<AcronisResource>> ListResourcesAsync(TriggerConfiguration configuration, string policyId, CancellationToken cancellationToken) =>
            Task.FromResult(new DiscoveryResult<AcronisResource>(DiscoveryStatus.Succeeded, []));
        public Task<ExecutionState> GetExecutionStateAsync(TriggerConfiguration configuration, ConfiguredTarget target, CancellationToken cancellationToken) =>
            Task.FromResult(ExecutionState.Idle);
        public Task<StartOutcome> StartPolicyAsync(TriggerConfiguration configuration, ConfiguredTarget target, CancellationToken cancellationToken, Action? onSend = null, Action? onPreSendFailure = null)
        {
            onSend?.Invoke();
            throw new OperationCanceledException(cancellationToken);
        }
    }



    private sealed class MutableClock
    {
        public TimeSpan Elapsed { get; private set; }
        public void Advance(TimeSpan duration) => Elapsed += duration;
    }

    private sealed class DeadlineCrossingTransport(MutableClock clock) : IAcronisTransport
    {
        private int stateReads;
        public int StartCount { get; private set; }

        public Task<TokenResult> RequestTokenAsync(TriggerConfiguration configuration, CancellationToken cancellationToken) =>
            Task.FromResult(TokenResult.Authenticated);

        public Task<DiscoveryResult<AcronisPolicy>> ListProtectionPoliciesAsync(TriggerConfiguration configuration, CancellationToken cancellationToken) =>
            Task.FromResult(new DiscoveryResult<AcronisPolicy>(DiscoveryStatus.Succeeded, []));

        public Task<DiscoveryResult<AcronisResource>> ListResourcesAsync(TriggerConfiguration configuration, string policyId, CancellationToken cancellationToken) =>
            Task.FromResult(new DiscoveryResult<AcronisResource>(DiscoveryStatus.Succeeded, []));

        public Task<ExecutionState> GetExecutionStateAsync(
            TriggerConfiguration configuration,
            ConfiguredTarget target,
            CancellationToken cancellationToken)
        {
            // The pre-start guard reports Idle; the observation status call simulates
            // a slow response that advances the wall clock past the deadline before
            // reporting Running.
            if (stateReads++ == 0) return Task.FromResult(ExecutionState.Idle);
            clock.Advance(TimeSpan.FromSeconds(10));
            return Task.FromResult(ExecutionState.Running);
        }

        public Task<StartOutcome> StartPolicyAsync(
            TriggerConfiguration configuration,
            ConfiguredTarget target,
            CancellationToken cancellationToken,
            Action? onSend = null,
            Action? onPreSendFailure = null)
        {
            StartCount++;
            return Task.FromResult(StartOutcome.Accepted);
        }
    }

    private sealed class RecordingPendingStore : IPendingStartStore
    {
        public DateTimeOffset? Marked { get; set; }

        public DateTimeOffset? Read() => Marked;
        public void Mark(DateTimeOffset sentAt) => Marked = sentAt;
        public void Clear() => Marked = null;
    }

    private static BackupTrigger Trigger(
        IAcronisTransport transport,
        List<TimeSpan>? delays = null,
        IPendingStartStore? pending = null,
        TimeSpan? observationWindow = null)
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
        public int StateReads => stateReads;

        public Task<TokenResult> RequestTokenAsync(TriggerConfiguration configuration, CancellationToken cancellationToken) =>
            Task.FromResult(TokenResult.Authenticated);

        public Task<DiscoveryResult<AcronisPolicy>> ListProtectionPoliciesAsync(TriggerConfiguration configuration, CancellationToken cancellationToken) =>
            Task.FromResult(new DiscoveryResult<AcronisPolicy>(DiscoveryStatus.Succeeded, []));

        public Task<DiscoveryResult<AcronisResource>> ListResourcesAsync(TriggerConfiguration configuration, string policyId, CancellationToken cancellationToken) =>
            Task.FromResult(new DiscoveryResult<AcronisResource>(DiscoveryStatus.Succeeded, []));

        public Task<ExecutionState> GetExecutionStateAsync(
            TriggerConfiguration configuration,
            ConfiguredTarget target,
            CancellationToken cancellationToken)
        {
            var state = States[Math.Min(stateReads, States.Length - 1)];
            stateReads++;
            return Task.FromResult(state);
        }

        public Task<StartOutcome> StartPolicyAsync(
            TriggerConfiguration configuration,
            ConfiguredTarget target,
            CancellationToken cancellationToken,
            Action? onSend = null,
            Action? onPreSendFailure = null)
        {
            StartCount++;
            StartedTargets.Add((target.PolicyId, target.ResourceId));
            onSend?.Invoke();
            return Task.FromResult(Start);
        }
    }
}
