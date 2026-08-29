using System.Diagnostics;

namespace AcronisBackupTrigger;

/// <summary>Outcome of reading the execution state Acronis reports for a policy on one resource.</summary>
public enum ExecutionState
{
    Idle,
    Running,
    AuthenticationFailed,
    ConnectivityFailed,
    AcronisRejected,
    UnexpectedResponse,
}

/// <summary>Result of asking Acronis to start a protection policy.</summary>
public enum StartOutcome
{
    /// <summary>HTTP 202: accepted for asynchronous execution.</summary>
    Accepted,

    /// <summary>HTTP 204: completed synchronously.</summary>
    CompletedSynchronously,

    /// <summary>Acronis refused the request, e.g. a disabled policy or a quota problem.</summary>
    Rejected,

    AuthenticationFailed,

    /// <summary>The request provably never reached Acronis.</summary>
    NotSent,

    /// <summary>
    /// The request may or may not have been accepted. It must never be retried,
    /// because Acronis may already have started a backup.
    /// </summary>
    OutcomeUnknown,
}

public enum TriggerOutcome
{
    ObservedRunning,
    AlreadyRunning,
    AcceptedNotObserved,
    TargetNotConfigured,
    AuthenticationFailed,
    ConnectivityFailed,
    AcronisRejected,
    OutcomeUnknown,
    StartOutstanding,
    UnexpectedResponse,
    CompletedSynchronously,
    TotalTimeout,
}

public sealed record TriggerResult(TriggerOutcome Outcome, string Detail);

/// <summary>
/// Starts the configured protection policy for the Configured resource, then waits
/// a bounded time for Acronis to report it running. Request acceptance alone is not
/// treated as success, and backup completion is never claimed.
/// </summary>
public sealed class BackupTrigger(
    IAcronisTransport transport,
    IPendingStartStore pendingStarts,
    Func<TimeSpan, CancellationToken, Task>? delayOverride = null,
    TimeSpan? observationWindow = null,
    Func<TimeSpan>? elapsedOverride = null)
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(3);

    private readonly Func<TimeSpan, CancellationToken, Task> delay =
        delayOverride ?? ((duration, token) => Task.Delay(duration, token));

    private readonly TimeSpan window = observationWindow ?? TimeSpan.FromSeconds(30);

    public async Task<TriggerResult> RunAsync(TriggerConfiguration configuration, CancellationToken cancellationToken)
    {
        if (configuration.PolicyId is not { Length: > 0 } policyId
            || configuration.ResourceId is not { Length: > 0 } resourceId)
        {
            return new TriggerResult(
                TriggerOutcome.TargetNotConfigured,
                "No protection policy and resource are configured. Run setup to choose a target.");
        }

        // A previous invocation sent a start request whose outcome never became known.
        // Resending could start a second backup, so refuse until an operator clears it.
        if (pendingStarts.Read() is { } pending)
        {
            return new TriggerResult(
                TriggerOutcome.StartOutstanding,
                $"A start request sent at {pending:u} has an unknown outcome. Check the Acronis console, then run clear-pending to allow new runs.");
        }

        var state = await transport.GetExecutionStateAsync(configuration, policyId, resourceId, cancellationToken);
        if (Guard(configuration, state) is { } refusal) return refusal;

        pendingStarts.Mark(DateTimeOffset.UtcNow);
        var start = await transport.StartPolicyAsync(configuration, policyId, resourceId, cancellationToken);

        switch (start)
        {
            case StartOutcome.Rejected:
                pendingStarts.Clear();
                return new TriggerResult(TriggerOutcome.AcronisRejected, "Acronis rejected the request to start the protection policy.");
            case StartOutcome.AuthenticationFailed:
                pendingStarts.Clear();
                return new TriggerResult(TriggerOutcome.AuthenticationFailed, "Acronis rejected the API client credentials.");
            case StartOutcome.NotSent:
                pendingStarts.Clear();
                return new TriggerResult(TriggerOutcome.ConnectivityFailed, "Acronis could not be reached, so no start request was sent.");
            case StartOutcome.CompletedSynchronously:
                // Acronis finished the request before replying, so polling for a
                // running state would only burn the observation window.
                pendingStarts.Clear();
                return new TriggerResult(
                    TriggerOutcome.CompletedSynchronously,
                    $"Acronis completed the request for {configuration.PolicyName} on {configuration.ResourceName} immediately. Check the Acronis console for the backup result.");
            case StartOutcome.OutcomeUnknown:
                return new TriggerResult(
                    TriggerOutcome.OutcomeUnknown,
                    "The start request outcome is unknown and was deliberately not retried. Check the Acronis console, then run clear-pending.");
        }

        return await ObserveStartAsync(configuration, policyId, resourceId, cancellationToken);
    }

    private TriggerResult? Guard(TriggerConfiguration configuration, ExecutionState state) => state switch
    {
        ExecutionState.Idle => null,
        ExecutionState.Running => new TriggerResult(
            TriggerOutcome.AlreadyRunning,
            $"{configuration.PolicyName} is already running on {configuration.ResourceName}. No new backup was requested."),
        ExecutionState.AuthenticationFailed => new TriggerResult(
            TriggerOutcome.AuthenticationFailed,
            "Acronis rejected the API client credentials, so no backup was requested."),
        ExecutionState.AcronisRejected => new TriggerResult(
            TriggerOutcome.AcronisRejected,
            "Acronis refused the execution-state request, so no backup was requested."),
        ExecutionState.UnexpectedResponse => new TriggerResult(
            TriggerOutcome.UnexpectedResponse,
            "Acronis returned an unrecognised execution-state response, so no backup was requested."),
        _ => new TriggerResult(
            TriggerOutcome.ConnectivityFailed,
            "The current execution state could not be read, so no backup was requested."),
    };

    private async Task<TriggerResult> ObserveStartAsync(
        TriggerConfiguration configuration,
        string policyId,
        string resourceId,
        CancellationToken cancellationToken)
    {
        // Measure wall clock: token acquisition, HTTP latency, and status retries all
        // consume the observation window, not only the delays we schedule.
        var elapsed = elapsedOverride ?? StopwatchElapsed();

        while (elapsed() < window)
        {
            var remaining = window - elapsed();
            await delay(PollInterval < remaining ? PollInterval : remaining, cancellationToken);

            var state = await transport.GetExecutionStateAsync(configuration, policyId, resourceId, cancellationToken);
            if (state == ExecutionState.Running)
            {
                pendingStarts.Clear();
                return new TriggerResult(
                    TriggerOutcome.ObservedRunning,
                    $"{configuration.PolicyName} is running on {configuration.ResourceName}. Monitor completion in the Acronis console.");
            }
        }

        // Acronis confirmed acceptance, so the request is not ambiguous: clear the
        // marker. Blocking every later invocation here would silently stop backups on
        // an unattended hook, and the already-running guard still prevents an overlap.
        pendingStarts.Clear();
        return new TriggerResult(
            TriggerOutcome.AcceptedNotObserved,
            $"Acronis accepted the request, but {configuration.PolicyName} was not observed running within {window.TotalSeconds:0} seconds. Check the Acronis console.");
    }

    private static Func<TimeSpan> StopwatchElapsed()
    {
        var stopwatch = Stopwatch.StartNew();
        return () => stopwatch.Elapsed;
    }
}
