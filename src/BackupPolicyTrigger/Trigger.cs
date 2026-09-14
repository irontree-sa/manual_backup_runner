namespace BackupPolicyTrigger;

/// <summary>
/// Runs the configured protection policy and reports a typed outcome plus the
/// process exit code. The concrete module owns the Acronis decision, the outcome
/// translation, the result emission, and the best-effort audit record, so the
/// command host never has to know how a run is decided.
/// </summary>
public interface ITrigger
{
    Task<TriggerExecutionResult> RunAsync(TriggerConfiguration configuration, CancellationToken cancellationToken);
}

public sealed record TriggerExecutionResult(TriggerOutcome Outcome, int ExitCode, string Detail);

public sealed class Trigger(
    Func<IAcronisTransport> transportFactory,
    IPendingStartStore pendingStarts,
    Action<string>? audit = null,
    TextWriter? output = null,
    TextWriter? error = null,
    Func<TimeSpan, CancellationToken, Task>? delayOverride = null,
    TimeSpan? observationWindow = null,
    Func<TimeSpan>? elapsedOverride = null) : ITrigger
{
    public async Task<TriggerExecutionResult> RunAsync(TriggerConfiguration configuration, CancellationToken cancellationToken)
    {
        var trigger = new BackupTrigger(transportFactory(), pendingStarts, delayOverride, observationWindow, elapsedOverride);

        TriggerResult result;
        try
        {
            result = await trigger.RunAsync(configuration, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            // The unattended invocation budget expired during the run. The backup may
            // already have started, so the guidance is deliberately start-agnostic.
            result = new TriggerResult(
                TriggerOutcome.TotalTimeout,
                "The run exceeded its time budget. Check the Acronis console before running again.");
        }

        var exit = result.Outcome switch
        {
            TriggerOutcome.ObservedRunning or TriggerOutcome.CompletedSynchronously => ExitCodes.Success,
            TriggerOutcome.AlreadyRunning => ExitCodes.AlreadyRunning,
            TriggerOutcome.AcceptedNotObserved => ExitCodes.AcceptedNotObserved,
            TriggerOutcome.TargetNotConfigured => ExitCodes.RunUnavailable,
            TriggerOutcome.AuthenticationFailed => ExitCodes.RunAuthenticationFailed,
            TriggerOutcome.ConnectivityFailed => ExitCodes.RunConnectivityFailed,
            TriggerOutcome.AcronisRejected => ExitCodes.AcronisRejected,
            TriggerOutcome.StartOutstanding => ExitCodes.StartOutstanding,
            TriggerOutcome.UnexpectedResponse => ExitCodes.UnexpectedResponse,
            TriggerOutcome.TotalTimeout => ExitCodes.TotalTimeout,
            _ => ExitCodes.StartOutcomeUnknown,
        };

        // Result emission is best-effort: a failing stdout/stderr must never replace the
        // already-determined exit code, or a post-backup caller could retry a completed
        // trigger after the no-resend marker has been cleared.
        var line = $"{result.Outcome}: {result.Detail}";
        try
        {
            if (exit == ExitCodes.Success) output?.WriteLine(line);
            else error?.WriteLine(line);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }

        // The audit record carries only the safe outcome and exit code, never the
        // detail (which may embed target names) or any credential material.
        try
        {
            audit?.Invoke($"run: exit={exit} outcome={result.Outcome}");
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }

        return new TriggerExecutionResult(result.Outcome, exit, result.Detail);
    }
}
