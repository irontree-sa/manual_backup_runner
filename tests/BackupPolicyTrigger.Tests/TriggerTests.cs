using BackupPolicyTrigger;

namespace BackupPolicyTrigger.Tests;

public sealed class TriggerTests
{
    private static readonly TriggerConfiguration Configured = new(
        "https://eu2.acronis.cloud", "client-id", "secret",
        new ConfiguredTarget("policy-1", "Windows Backup", "resource-1", "SERVER-01"));

    [Fact]
    public async Task Run_returns_typed_outcome_and_translated_exit_code()
    {
        var result = await TriggerFor(StartOutcome.CompletedSynchronously).RunAsync(Configured, CancellationToken.None);

        Assert.Equal(TriggerOutcome.CompletedSynchronously, result.Outcome);
        Assert.Equal(ExitCodes.Success, result.ExitCode);
    }

    [Fact]
    public async Task Run_writes_sanitized_audit_record_after_a_configured_result()
    {
        var entries = new List<string>();
        var result = await TriggerFor(StartOutcome.Accepted, entries.Add).RunAsync(Configured, CancellationToken.None);

        Assert.Equal(ExitCodes.AcceptedNotObserved, result.ExitCode);
        Assert.Single(entries);
        Assert.DoesNotContain("secret", entries[0], StringComparison.OrdinalIgnoreCase);
    }

    private static ITrigger TriggerFor(StartOutcome start, Action<string>? audit = null) =>
        new Trigger(
            () => new FakeAcronisTransport { State = ExecutionState.Idle, Start = start },
            new NullPendingStartStore(),
            audit);
}
