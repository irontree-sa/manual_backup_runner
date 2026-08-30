using AcronisBackupTrigger;

namespace AcronisBackupTrigger.Tests;

public sealed class CommandHostTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
    private readonly StringWriter output = new();
    private readonly StringWriter error = new();

    [Fact]
    public async Task No_arguments_on_an_unconfigured_machine_reports_missing_configuration()
    {
        var exit = await Host([], Store()).RunAsync([]);

        Assert.Equal(ExitCodes.ConfigurationMissing, exit);
        Assert.Contains("Configuration is missing", error.ToString());
    }

    [Fact]
    public async Task Setup_saves_configuration_and_never_echoes_the_secret()
    {
        var store = Store();

        var exit = await Host(["https://eu2.acronis.cloud", "client-id", "1", "1"], store).RunAsync(["setup"]);

        Assert.Equal(ExitCodes.Success, exit);
        Assert.Equal(
            new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "typed-secret", new ConfiguredTarget("policy-1", "Daily", "resource-1", "SERVER-01")),
            store.Load());
        Assert.DoesNotContain("typed-secret", output.ToString());
        Assert.DoesNotContain("typed-secret", error.ToString());
    }

    [Fact]
    public async Task Setup_keeps_existing_configuration_unless_replacement_is_confirmed()
    {
        var store = Store();
        var original = new TriggerConfiguration("https://eu2.acronis.cloud", "original-id", "original-secret");
        store.Save(original);

        var exit = await Host(["no"], store).RunAsync(["setup"]);

        Assert.Equal(ExitCodes.Success, exit);
        Assert.Equal(original, store.Load());
        Assert.Contains("original-id", output.ToString());
        Assert.DoesNotContain("original-secret", output.ToString());
    }

    [Fact]
    public async Task Setup_creates_protected_storage_before_policy_discovery()
    {
        var store = Store();
        var transport = new AssertingStorageTransport(directory);

        var host = new CommandHost(
            store,
            () => transport,
            new StringReader(string.Join(Environment.NewLine, ["https://eu2.acronis.cloud", "client-id"])),
            output,
            error,
            () => "typed-secret",
            UnusedTrigger());

        var exit = await host.RunAsync(["setup"]);

        Assert.Equal(ExitCodes.DiscoveryFailed, exit);
    }

    [Fact]
    public async Task Setup_replaces_existing_configuration_when_confirmed()
    {
        var store = Store();
        store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "original-id", "original-secret"));

        var exit = await Host(["REPLACE", "https://us5.acronis.cloud", "new-id", "1", "1"], store).RunAsync(["setup"]);

        Assert.Equal(ExitCodes.Success, exit);
        Assert.Equal(
            new TriggerConfiguration("https://us5.acronis.cloud", "new-id", "typed-secret", new ConfiguredTarget("policy-1", "Daily", "resource-1", "SERVER-01")),
            store.Load());
    }

    [Fact]
    public async Task Reset_removes_configuration_and_advises_revocation()
    {
        var store = Store();
        store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "secret"));

        var exit = await Host([], store).RunAsync(["reset"]);

        Assert.Equal(ExitCodes.Success, exit);
        Assert.Null(store.Load());
        Assert.Contains("Revoke", output.ToString());
    }

    [Fact]
    public async Task Diagnose_reports_missing_configuration()
    {
        var exit = await Host([], Store()).RunAsync(["diagnose"]);

        Assert.Equal(ExitCodes.ConfigurationMissing, exit);
        Assert.Contains("Configuration is missing", error.ToString());
    }

    [Theory]
    [InlineData(TokenResult.Authenticated, ExitCodes.Success)]
    [InlineData(TokenResult.AuthenticationFailed, ExitCodes.DiagnosticsFailed)]
    [InlineData(TokenResult.InvalidDataCenterUrl, ExitCodes.DiagnosticsFailed)]
    public async Task Diagnose_translates_transport_outcome_to_exit_code(TokenResult transportResult, int expectedExit)
    {
        var store = Store();
        store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "secret"));

        var exit = await Host([], store, transportResult).RunAsync(["diagnose"]);

        Assert.Equal(expectedExit, exit);
        Assert.Contains(transportResult.ToString(), output.ToString());
    }

    [Fact]
    public async Task Diagnose_reports_inaccessible_configuration_distinctly_from_missing_configuration()
    {
        var host = Host([], new ConfigurationStore(directory, new DeniedProtector()));
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Path.Combine(directory, "configuration.dat"), [1, 2, 3]);

        var exit = await host.RunAsync(["diagnose"]);

        Assert.Equal(ExitCodes.ConfigurationInaccessible, exit);
        Assert.Contains("not accessible", error.ToString());
    }

    [Fact]
    public async Task Diagnose_reports_undecryptable_configuration_distinctly()
    {
        var host = Host([], new ConfigurationStore(directory, new CorruptProtector()));
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Path.Combine(directory, "configuration.dat"), [1, 2, 3]);

        var exit = await host.RunAsync(["diagnose"]);

        Assert.Equal(ExitCodes.ConfigurationUnreadable, exit);
        Assert.Contains("Run setup", error.ToString());
    }
    [Theory]
    [InlineData("setup")]
    [InlineData("reset")]
    [InlineData("select-target")]
    [InlineData("clear-pending")]
    public async Task State_changing_commands_require_an_elevated_administrator(string command)
    {
        var store = new ConfigurationStore(directory, new DeniedProtector());
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Path.Combine(directory, "configuration.dat"), [1, 2, 3]);

        var host = new CommandHost(
            store,
            () => throw new InvalidOperationException("transport must not be constructed"),
            new StringReader(""),
            output,
            error,
            () => throw new InvalidOperationException("secret must not be read"),
            UnusedTrigger(),
            administratorGate: new DeniedAdministratorGate());

        var exit = await host.RunAsync([command]);

        Assert.Equal(ExitCodes.AdministratorRequired, exit);
        Assert.Contains("elevated Administrator", error.ToString());
    }

    [Fact]
    public async Task A_throwing_audit_never_replaces_the_trigger_exit_code()
    {
        var store = Store();
        store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "secret",
            new ConfiguredTarget("policy-1", "Daily", "resource-1", "SERVER-01")));
        var transport = new FakeAcronisTransport
        {
            State = ExecutionState.Idle,
            Start = StartOutcome.CompletedSynchronously,
        };

        var host = new CommandHost(
            store,
            () => transport,
            new StringReader(""),
            output,
            error,
            () => "typed-secret",
            new Trigger(
                () => transport,
                new NullPendingStartStore(),
                audit: _ => throw new IOException("disk full"),
                output: output,
                error: error));

        var exit = await host.RunAsync([]);

        Assert.Equal(ExitCodes.Success, exit);
    }

    [Fact]
    public async Task A_throwing_audit_never_replaces_a_denied_administrator_gate()
    {
        var store = new ConfigurationStore(directory, new DeniedProtector());
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Path.Combine(directory, "configuration.dat"), [1, 2, 3]);

        var host = new CommandHost(
            store,
            () => throw new InvalidOperationException("transport must not be constructed"),
            new StringReader(""),
            output,
            error,
            () => throw new InvalidOperationException("secret must not be read"),
            new Trigger(
                () => throw new InvalidOperationException("transport must not be constructed"),
                new NullPendingStartStore(),
                audit: _ => throw new UnauthorizedAccessException("log denied"),
                output: output,
                error: error),
            administratorGate: new DeniedAdministratorGate());

        var exit = await host.RunAsync(["setup"]);

        Assert.Equal(ExitCodes.AdministratorRequired, exit);
    }
    [Theory]
    [InlineData(StartOutcome.CompletedSynchronously, ExitCodes.Success)]
    [InlineData(StartOutcome.Accepted, ExitCodes.AcceptedNotObserved)]
    public async Task A_throwing_output_writer_never_replaces_the_trigger_exit_code(StartOutcome start, int expectedExit)
    {
        var store = Store();
        store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "secret",
            new ConfiguredTarget("policy-1", "Daily", "resource-1", "SERVER-01")));
        var transport = new FakeAcronisTransport
        {
            State = ExecutionState.Idle,
            Start = start,
        };
        var clock = new MutableClock();

        var host = new CommandHost(
            store,
            () => transport,
            new StringReader(""),
            new ThrowingWriter(),
            error,
            () => "typed-secret",
            new Trigger(
                () => transport,
                new NullPendingStartStore(),
                output: new ThrowingWriter(),
                error: error,
                delayOverride: (d, _) => { clock.Advance(d); return Task.CompletedTask; },
                observationWindow: TimeSpan.FromSeconds(1),
                elapsedOverride: () => clock.Elapsed));

        var exit = await host.RunAsync([]);

        Assert.Equal(expectedExit, exit);
    }

    [Fact]
    public async Task A_throwing_error_writer_never_replaces_a_successful_trigger_exit_code()
    {
        var store = Store();
        store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "secret",
            new ConfiguredTarget("policy-1", "Daily", "resource-1", "SERVER-01")));
        var transport = new FakeAcronisTransport
        {
            State = ExecutionState.Idle,
            Start = StartOutcome.CompletedSynchronously,
        };
        var clock = new MutableClock();

        var host = new CommandHost(
            store,
            () => transport,
            new StringReader(""),
            output,
            new ThrowingWriter(),
            () => "typed-secret",
            new Trigger(
                () => transport,
                new NullPendingStartStore(),
                output: output,
                error: new ThrowingWriter(),
                delayOverride: (d, _) => { clock.Advance(d); return Task.CompletedTask; },
                observationWindow: TimeSpan.FromSeconds(1),
                elapsedOverride: () => clock.Elapsed));

        var exit = await host.RunAsync([]);

        Assert.Equal(ExitCodes.Success, exit);
    }

    [Fact]
    public async Task An_unexpected_start_response_maps_to_exit_20()
    {
        var store = Store();
        store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "secret",
            new ConfiguredTarget("policy-1", "Daily", "resource-1", "SERVER-01")));
        var transport = new FakeAcronisTransport
        {
            State = ExecutionState.Idle,
            Start = StartOutcome.UnexpectedResponse,
        };
        var clock = new MutableClock();

        var host = new CommandHost(
            store,
            () => transport,
            new StringReader(""),
            output,
            error,
            () => "typed-secret",
            new Trigger(
                () => transport,
                new NullPendingStartStore(),
                output: output,
                error: error,
                delayOverride: (d, _) => { clock.Advance(d); return Task.CompletedTask; },
                observationWindow: TimeSpan.FromSeconds(1),
                elapsedOverride: () => clock.Elapsed));

        var exit = await host.RunAsync([]);

        Assert.Equal(ExitCodes.UnexpectedResponse, exit);
        Assert.Contains("UnexpectedResponse", error.ToString());
    }
    [Fact]
    public async Task Run_command_returns_the_trigger_exit_code_without_mapping_outcome()
    {
        var store = Store();
        store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "secret",
            new ConfiguredTarget("policy-1", "Daily", "resource-1", "SERVER-01")));

        var host = new CommandHost(
            store,
            () => throw new InvalidOperationException("transport must not be constructed"),
            new StringReader(""),
            output,
            error,
            () => "typed-secret",
            new StubTrigger(new TriggerExecutionResult(TriggerOutcome.AcronisRejected, ExitCodes.AcronisRejected, "rejected")));

        Assert.Equal(ExitCodes.AcronisRejected, await host.RunAsync([]));
    }

    private sealed class StubTrigger(TriggerExecutionResult result) : ITrigger
    {
        public Task<TriggerExecutionResult> RunAsync(TriggerConfiguration configuration, CancellationToken cancellationToken) =>
            Task.FromResult(result);
    }


    private sealed class MutableClock
    {
        public TimeSpan Elapsed { get; private set; }
        public void Advance(TimeSpan duration) => Elapsed += duration;
    }

    private sealed class ThrowingWriter : TextWriter
    {
        public override System.Text.Encoding Encoding => System.Text.Encoding.UTF8;
        public override void Write(char value) => throw new IOException("broken pipe");
        public override void Write(string? value) => throw new IOException("broken pipe");
        public override void WriteLine(string? value) => throw new IOException("broken pipe");
    }


    [Fact]
    public async Task Diagnose_reports_a_non_zero_exit_when_the_saved_target_is_unreadable()
    {
        var store = Store();
        store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "secret",
            new ConfiguredTarget("policy-1", "Daily", "resource-1", "SERVER-01")));
        var transport = new FakeAcronisTransport { State = ExecutionState.AcronisRejected };

        var host = new CommandHost(
            store,
            () => transport,
            new StringReader(""),
            output,
            error,
            () => "typed-secret",
            UnusedTrigger());

        var exit = await host.RunAsync(["diagnose"]);

        Assert.Equal(ExitCodes.DiagnosticsFailed, exit);
        Assert.Contains("TargetRejected", output.ToString());
    }

    [Fact]
    public async Task Diagnose_reports_success_when_the_saved_target_is_idle()
    {
        var store = Store();
        store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "secret",
            new ConfiguredTarget("policy-1", "Daily", "resource-1", "SERVER-01")));
        var transport = new FakeAcronisTransport { State = ExecutionState.Idle };

        var host = new CommandHost(
            store,
            () => transport,
            new StringReader(""),
            output,
            error,
            () => "typed-secret",
            UnusedTrigger());

        var exit = await host.RunAsync(["diagnose"]);

        Assert.Equal(ExitCodes.Success, exit);
        Assert.Contains("TargetIdle", output.ToString());
    }

    [Theory]
    [InlineData("", "resource-1")]
    [InlineData("policy-1", "")]
    public async Task Diagnose_does_not_read_target_state_when_an_execution_id_is_empty(string policyId, string resourceId)
    {
        var store = Store();
        store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "secret",
            new ConfiguredTarget(policyId, "Daily", resourceId, "SERVER-01")));
        var transport = new FakeAcronisTransport { State = ExecutionState.AcronisRejected };

        var host = new CommandHost(
            store,
            () => transport,
            new StringReader(""),
            output,
            error,
            () => "typed-secret",
            UnusedTrigger());

        var exit = await host.RunAsync(["diagnose"]);

        Assert.Equal(ExitCodes.Success, exit);
        Assert.Equal(0, transport.StateReadCount);
    }

    [Fact]
    public async Task Setup_requires_REPLACE_before_overwriting_unreadable_configuration()
    {
        var store = new ConfigurationStore(directory, new CorruptProtector());
        Directory.CreateDirectory(directory);
        var original = new byte[] { 1, 2, 3, 4, 5 };
        File.WriteAllBytes(Path.Combine(directory, "configuration.dat"), original);

        var host = new CommandHost(
            store,
            () => throw new InvalidOperationException("transport must not be constructed"),
            new StringReader("no"),
            output,
            error,
            () => throw new InvalidOperationException("secret must not be read"),
            UnusedTrigger());

        var exit = await host.RunAsync(["setup"]);

        Assert.Equal(ExitCodes.Success, exit);
        Assert.Equal(original, File.ReadAllBytes(Path.Combine(directory, "configuration.dat")));
        Assert.Contains("REPLACE", output.ToString());
    }

    [Theory]
    [InlineData("diagnose")]
    [InlineData("list-policies")]
    [InlineData("list-resources")]
    public async Task Budget_cancellation_returns_total_timeout_for_non_run_commands(string command)
    {
        var store = Store();
        store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "secret",
            new ConfiguredTarget("policy-1", "Daily", "resource-1", "SERVER-01")));
        var transport = new CancellingTransport();

        var host = new CommandHost(
            store,
            () => transport,
            new StringReader(""),
            output,
            error,
            () => "typed-secret",
            UnusedTrigger());

        using var budget = new CancellationTokenSource();
        budget.Cancel();

        var exit = await host.RunAsync([command], budget.Token);

        Assert.Equal(ExitCodes.TotalTimeout, exit);

        Assert.Contains("time budget", error.ToString());
    }

    private sealed class CancellingTransport : IAcronisTransport
    {
        public Task<TokenResult> RequestTokenAsync(TriggerConfiguration configuration, CancellationToken cancellationToken) =>
            throw new OperationCanceledException(cancellationToken);

        public Task<DiscoveryResult<AcronisPolicy>> ListProtectionPoliciesAsync(TriggerConfiguration configuration, CancellationToken cancellationToken) =>
            throw new OperationCanceledException(cancellationToken);

        public Task<DiscoveryResult<AcronisResource>> ListResourcesAsync(TriggerConfiguration configuration, string policyId, CancellationToken cancellationToken) =>
            throw new OperationCanceledException(cancellationToken);

        public Task<ExecutionState> GetExecutionStateAsync(TriggerConfiguration configuration, ConfiguredTarget target, CancellationToken cancellationToken) =>
            throw new OperationCanceledException(cancellationToken);

        public Task<StartOutcome> StartPolicyAsync(TriggerConfiguration configuration, ConfiguredTarget target, CancellationToken cancellationToken, Action? onSend = null, Action? onPreSendFailure = null) =>
            throw new OperationCanceledException(cancellationToken);
    }

    private sealed class AssertingStorageTransport(string directory) : IAcronisTransport
    {
        public Task<TokenResult> RequestTokenAsync(TriggerConfiguration configuration, CancellationToken cancellationToken) =>
            Task.FromResult(TokenResult.Authenticated);

        public Task<DiscoveryResult<AcronisPolicy>> ListProtectionPoliciesAsync(
            TriggerConfiguration configuration,
            CancellationToken cancellationToken)
        {
            Assert.True(Directory.Exists(directory), "Protected storage must exist before policy discovery.");
            return Task.FromResult(DiscoveryResult<AcronisPolicy>.Failed(DiscoveryStatus.ConnectivityFailed));
        }

        public Task<DiscoveryResult<AcronisResource>> ListResourcesAsync(
            TriggerConfiguration configuration,
            string policyId,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("resources must not be listed after a failed policy discovery");

        public Task<ExecutionState> GetExecutionStateAsync(
            TriggerConfiguration configuration,
            ConfiguredTarget target,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("state must not be read during setup");

        public Task<StartOutcome> StartPolicyAsync(
            TriggerConfiguration configuration,
            ConfiguredTarget target,
            CancellationToken cancellationToken,
            Action? onSend = null,
            Action? onPreSendFailure = null) =>
            throw new InvalidOperationException("start must not be invoked during setup");
    }

    private sealed class DeniedAdministratorGate : IAdministratorGate
    {
        public bool IsElevated => false;
    }

    private ConfigurationStore Store() => new(directory, new ReversingProtector());

    private CommandHost Host(string[] lines, ConfigurationStore store, TokenResult transportResult = TokenResult.Authenticated) =>
        new(store,
            () => new FakeAcronisTransport(transportResult)
            {
                Policies = new(DiscoveryStatus.Succeeded, [new AcronisPolicy("policy-1", "Daily")]),
                Resources = new(DiscoveryStatus.Succeeded, [new AcronisResource("resource-1", "SERVER-01")]),
            },
            new StringReader(string.Join(Environment.NewLine, lines)),
            output,
            error,
            () => "typed-secret",
            UnusedTrigger());

    private static ITrigger UnusedTrigger() =>
        new Trigger(
            () => throw new InvalidOperationException("trigger must not be constructed"),
            new NullPendingStartStore(),
            output: TextWriter.Null,
            error: TextWriter.Null);

    public void Dispose()
    {
        output.Dispose();
        error.Dispose();
        if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }



    private sealed class ReversingProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => plaintext.Reverse().ToArray();
        public byte[] Unprotect(byte[] ciphertext) => ciphertext.Reverse().ToArray();
    }

    private sealed class DeniedProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => plaintext;
        public byte[] Unprotect(byte[] ciphertext) => throw new UnauthorizedAccessException();
    }

    private sealed class CorruptProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => plaintext;
        public byte[] Unprotect(byte[] ciphertext) => throw new System.Security.Cryptography.CryptographicException();
    }
}
