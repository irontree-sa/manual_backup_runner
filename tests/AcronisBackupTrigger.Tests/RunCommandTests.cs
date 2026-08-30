using AcronisBackupTrigger;

namespace AcronisBackupTrigger.Tests;

public sealed class RunCommandTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
    private readonly StringWriter output = new();
    private readonly StringWriter error = new();
    private readonly List<string> logged = [];

    private static readonly TriggerConfiguration Configured = new(
        "https://eu2.acronis.cloud", "client-id", "secret",
        new ConfiguredTarget("policy-1", "Windows Backup", "resource-1", "SERVER-01"));

    [Theory]
    [InlineData(ExecutionState.Running, StartOutcome.Accepted, ExitCodes.AlreadyRunning)]
    [InlineData(ExecutionState.ConnectivityFailed, StartOutcome.Accepted, ExitCodes.RunConnectivityFailed)]
    [InlineData(ExecutionState.AuthenticationFailed, StartOutcome.Accepted, ExitCodes.RunAuthenticationFailed)]
    [InlineData(ExecutionState.UnexpectedResponse, StartOutcome.Accepted, ExitCodes.UnexpectedResponse)]
    [InlineData(ExecutionState.Idle, StartOutcome.Rejected, ExitCodes.AcronisRejected)]
    [InlineData(ExecutionState.Idle, StartOutcome.AuthenticationFailed, ExitCodes.RunAuthenticationFailed)]
    [InlineData(ExecutionState.Idle, StartOutcome.NotSent, ExitCodes.RunConnectivityFailed)]
    [InlineData(ExecutionState.Idle, StartOutcome.UnexpectedResponse, ExitCodes.UnexpectedResponse)]
    [InlineData(ExecutionState.Idle, StartOutcome.UnexpectedResponseAfterSend, ExitCodes.UnexpectedResponse)]
    [InlineData(ExecutionState.Idle, StartOutcome.OutcomeUnknown, ExitCodes.StartOutcomeUnknown)]
    public async Task Run_reports_a_distinct_exit_code_per_outcome(ExecutionState state, StartOutcome start, int expected)
    {
        var store = Store();
        store.Save(Configured);
        var transport = new FakeAcronisTransport { State = state, Start = start };

        var exit = await Host(store, transport).RunAsync([]);

        Assert.Equal(expected, exit);
        Assert.Contains($"exit={expected}", string.Join("\n", logged));
    }

    [Fact]
    public async Task Run_succeeds_when_the_policy_is_observed_running()
    {
        var store = Store();
        store.Save(Configured);
        var transport = new SequencedTransport([ExecutionState.Idle, ExecutionState.Running]);

        var exit = await Host(store, transport).RunAsync([]);

        Assert.Equal(ExitCodes.Success, exit);
        Assert.Contains("ObservedRunning", output.ToString());
        Assert.Contains("Acronis console", output.ToString());
    }

    [Fact]
    public async Task Run_requires_a_configured_target()
    {
        var store = Store();
        store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "secret"));

        var exit = await Host(store, new FakeAcronisTransport()).RunAsync([]);

        Assert.Equal(ExitCodes.RunUnavailable, exit);
        Assert.Contains("Run setup", error.ToString());
    }

    [Fact]
    public async Task An_unknown_command_does_not_start_a_backup()
    {
        var store = Store();
        store.Save(Configured);
        var transport = new FakeAcronisTransport { State = ExecutionState.Idle };

        var exit = await Host(store, transport).RunAsync(["client_secret=super-secret-value"]);

        Assert.Equal(ExitCodes.UnknownCommand, exit);
        Assert.Equal(0, transport.StartCount);
        Assert.Contains("Unknown command", error.ToString());
        Assert.DoesNotContain("super-secret-value", string.Join("\n", logged));
    }

    [Fact]
    public void Log_rotates_at_the_size_bound_and_keeps_one_previous_file()
    {
        var log = new RotatingLog(directory, maxBytes: 256);

        for (var index = 0; index < 40; index++) log.Write($"run: entry {index} padded with text to grow the file");

        Assert.True(File.Exists(Path.Combine(directory, "trigger.log")));
        Assert.True(File.Exists(Path.Combine(directory, "trigger.log.1")));
        Assert.Empty(Directory.GetFiles(directory, "trigger.log.2"));
        Assert.All(
            Directory.GetFiles(directory, "trigger.log*"),
            file => Assert.True(new FileInfo(file).Length <= 256, $"{file} exceeded the size bound"));
    }

    [Fact]
    public void Log_truncates_a_single_event_larger_than_the_bound()
    {
        var log = new RotatingLog(directory, maxBytes: 128);

        log.Write(new string('x', 4096));

        var file = new FileInfo(Path.Combine(directory, "trigger.log"));
        Assert.True(file.Length <= 128, $"log grew to {file.Length} bytes");
        Assert.Contains("[truncated event]", File.ReadAllText(file.FullName));
    }

    [Fact]
    public void Log_refuses_credential_material()
    {
        var log = new RotatingLog(directory);

        log.Write("token response Bearer eyJ0abc");
        log.Write("run: exit=0 outcome=ObservedRunning");

        var contents = File.ReadAllText(Path.Combine(directory, "trigger.log"));
        Assert.DoesNotContain("eyJ0abc", contents);
        Assert.Contains("[redacted", contents);
        Assert.Contains("outcome=ObservedRunning", contents);
    }

    private ConfigurationStore Store() => new(directory, new ReversingProtector());

    private CommandHost Host(ConfigurationStore store, IAcronisTransport transport)
    {
        var elapsed = TimeSpan.Zero;
        return new CommandHost(
            store,
            () => transport,
            new StringReader(""),
            output,
            error,
            () => "typed-secret",
            new Trigger(
                () => transport,
                new NullPendingStartStore(),
                logged.Add,
                output,
                error,
                (duration, _) =>
                {
                    elapsed += duration;
                    return Task.CompletedTask;
                },
                TimeSpan.FromSeconds(9),
                () => elapsed));
    }

    public void Dispose()
    {
        output.Dispose();
        error.Dispose();
        if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }

    private sealed class SequencedTransport(ExecutionState[] states) : IAcronisTransport
    {
        private int reads;

        public Task<TokenResult> RequestTokenAsync(TriggerConfiguration configuration, CancellationToken cancellationToken) =>
            Task.FromResult(TokenResult.Authenticated);

        public Task<DiscoveryResult<AcronisPolicy>> ListProtectionPoliciesAsync(TriggerConfiguration configuration, CancellationToken cancellationToken) =>
            Task.FromResult(new DiscoveryResult<AcronisPolicy>(DiscoveryStatus.Succeeded, []));

        public Task<DiscoveryResult<AcronisResource>> ListResourcesAsync(TriggerConfiguration configuration, string policyId, CancellationToken cancellationToken) =>
            Task.FromResult(new DiscoveryResult<AcronisResource>(DiscoveryStatus.Succeeded, []));

        public Task<ExecutionState> GetExecutionStateAsync(TriggerConfiguration configuration, ConfiguredTarget target, CancellationToken cancellationToken)
        {
            var state = states[Math.Min(reads, states.Length - 1)];
            reads++;
            return Task.FromResult(state);
        }

        public Task<StartOutcome> StartPolicyAsync(TriggerConfiguration configuration, ConfiguredTarget target, CancellationToken cancellationToken, Action? onSend = null, Action? onPreSendFailure = null) =>
            Task.FromResult(StartOutcome.Accepted);
    }

    private sealed class ReversingProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => plaintext.Reverse().ToArray();
        public byte[] Unprotect(byte[] ciphertext) => ciphertext.Reverse().ToArray();
    }
}
