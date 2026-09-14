using BackupPolicyTrigger;

namespace BackupPolicyTrigger.Tests;

public sealed class TargetSelectionTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
    private readonly StringWriter output = new();
    private readonly StringWriter error = new();

    private static readonly AcronisPolicy Daily = new("11111111-1111-1111-1111-111111111111", "Servers daily");
    private static readonly AcronisPolicy Hourly = new("33333333-3333-3333-3333-333333333333", "SQL hourly");
    private static readonly AcronisResource Sql = new("55555555-5555-5555-5555-555555555555", "SQL-01");
    private static readonly AcronisResource Web = new("66666666-6666-6666-6666-666666666666", "WEB-01");

    [Fact]
    public async Task List_policies_shows_each_policy_name_and_id_without_changing_configuration()
    {
        var store = Store();
        var saved = Configured();
        store.Save(saved);
        var transport = new FakeAcronisTransport { Policies = new(DiscoveryStatus.Succeeded, [Daily, Hourly]) };

        var exit = await Host([], store, transport).RunAsync(["list-policies"]);

        Assert.Equal(ExitCodes.Success, exit);
        Assert.Contains("Servers daily", output.ToString());
        Assert.Contains(Daily.Id, output.ToString());
        Assert.Contains("SQL hourly", output.ToString());
        Assert.Equal(saved, store.Load());
    }

    [Fact]
    public async Task List_resources_lists_only_resources_attached_to_the_configured_policy()
    {
        var store = Store();
        store.Save(Configured());
        var transport = new FakeAcronisTransport { Resources = new(DiscoveryStatus.Succeeded, [Sql]) };

        var exit = await Host([], store, transport).RunAsync(["list-resources"]);

        Assert.Equal(ExitCodes.Success, exit);
        Assert.Equal([Daily.Id], transport.RequestedPolicyIds);
        Assert.Contains("SQL-01", output.ToString());
        Assert.Contains(Sql.Id, output.ToString());
    }

    [Fact]
    public async Task List_policies_reports_discovery_failure_distinctly()
    {
        var store = Store();
        store.Save(Configured());
        var transport = new FakeAcronisTransport { Policies = DiscoveryResult<AcronisPolicy>.Failed(DiscoveryStatus.AuthenticationFailed) };

        var exit = await Host([], store, transport).RunAsync(["list-policies"]);

        Assert.Equal(ExitCodes.DiscoveryFailed, exit);
        Assert.Contains("AuthenticationFailed", error.ToString());
    }

    [Fact]
    public async Task Setup_persists_the_selected_protection_policy_and_configured_resource()
    {
        var store = Store();
        var transport = new FakeAcronisTransport
        {
            Policies = new(DiscoveryStatus.Succeeded, [Daily, Hourly]),
            Resources = new(DiscoveryStatus.Succeeded, [Sql, Web]),
        };

        var exit = await Host(["https://eu2.acronis.cloud", "client-id", "2", "2"], store, transport).RunAsync(["setup"]);

        Assert.Equal(ExitCodes.Success, exit);
        var saved = store.Load()!;
        Assert.Equal(Hourly.Id, saved.Target!.PolicyId);
        Assert.Equal(Hourly.Name, saved.Target.PolicyName);
        Assert.Equal(Web.Id, saved.Target.ResourceId);
        Assert.Equal(Web.Name, saved.Target.ResourceName);
        Assert.Equal([Hourly.Id], transport.RequestedPolicyIds);
    }

    [Fact]
    public async Task Setup_rejects_a_selection_outside_the_offered_list()
    {
        var store = Store();
        var transport = new FakeAcronisTransport { Policies = new(DiscoveryStatus.Succeeded, [Daily]) };

        var exit = await Host(["https://eu2.acronis.cloud", "client-id", "9"], store, transport).RunAsync(["setup"]);

        Assert.Equal(ExitCodes.SelectionInvalid, exit);
        Assert.Null(store.Load());
    }

    [Fact]
    public async Task Setup_reports_when_the_policy_has_no_attached_resource()
    {
        var store = Store();
        var transport = new FakeAcronisTransport
        {
            Policies = new(DiscoveryStatus.Succeeded, [Daily]),
            Resources = new(DiscoveryStatus.Succeeded, []),
        };

        var exit = await Host(["https://eu2.acronis.cloud", "client-id", "1"], store, transport).RunAsync(["setup"]);

        Assert.Equal(ExitCodes.SelectionInvalid, exit);
        Assert.Contains("no protected resource", error.ToString());
        Assert.Null(store.Load());
    }

    [Fact]
    public async Task Setup_stores_nothing_when_policy_discovery_fails()
    {
        var store = Store();
        var transport = new FakeAcronisTransport { Policies = DiscoveryResult<AcronisPolicy>.Failed(DiscoveryStatus.ConnectivityFailed) };

        var exit = await Host(["https://eu2.acronis.cloud", "client-id"], store, transport).RunAsync(["setup"]);

        Assert.Equal(ExitCodes.DiscoveryFailed, exit);
        Assert.Null(store.Load());
    }

    [Fact]
    public async Task List_resources_requires_a_configured_policy()
    {
        var store = Store();
        store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "secret"));

        var exit = await Host([], store, new FakeAcronisTransport()).RunAsync(["list-resources"]);

        Assert.Equal(ExitCodes.ConfigurationMissing, exit);
        Assert.Contains("protection policy", error.ToString());
    }

    [Fact]
    public async Task Select_target_changes_the_target_without_re_entering_the_api_client()
    {
        var store = Store();
        store.Save(Configured());
        var transport = new FakeAcronisTransport
        {
            Policies = new(DiscoveryStatus.Succeeded, [Daily, Hourly]),
            Resources = new(DiscoveryStatus.Succeeded, [Web]),
        };

        var exit = await Host(["REPLACE", "2", "1"], store, transport).RunAsync(["select-target"]);

        Assert.Equal(ExitCodes.Success, exit);
        var saved = store.Load()!;
        Assert.Equal(Hourly.Id, saved.Target!.PolicyId);
        Assert.Equal(Web.Id, saved.Target.ResourceId);
        Assert.Equal("secret", saved.ClientSecret);
    }

    [Fact]
    public async Task Select_target_keeps_the_current_target_unless_replacement_is_confirmed()
    {
        var store = Store();
        var original = Configured();
        store.Save(original);
        var transport = new FakeAcronisTransport
        {
            Policies = new(DiscoveryStatus.Succeeded, [Daily, Hourly]),
            Resources = new(DiscoveryStatus.Succeeded, [Web]),
        };

        var exit = await Host(["no", "2", "1"], store, transport).RunAsync(["select-target"]);

        Assert.Equal(ExitCodes.Success, exit);
        Assert.Equal(original, store.Load());
        Assert.Contains(Daily.Name, output.ToString());
        Assert.Empty(transport.RequestedPolicyIds);
    }

    [Fact]
    public async Task Select_target_requires_existing_configuration()
    {
        var exit = await Host(["REPLACE", "1", "1"], Store(), new FakeAcronisTransport()).RunAsync(["select-target"]);

        Assert.Equal(ExitCodes.ConfigurationMissing, exit);
    }

    [Fact]
    public async Task List_resources_leaves_saved_configuration_untouched()
    {
        var store = Store();
        var saved = Configured();
        store.Save(saved);

        await Host([], store, new FakeAcronisTransport { Resources = new(DiscoveryStatus.Succeeded, [Web]) })
            .RunAsync(["list-resources"]);

        Assert.Equal(saved, store.Load());
    }

    private static TriggerConfiguration Configured() => new(
        "https://eu2.acronis.cloud", "client-id", "secret",
        new ConfiguredTarget(Daily.Id, Daily.Name, Sql.Id, Sql.Name));

    private ConfigurationStore Store() => new(directory, new ReversingProtector());

    private CommandHost Host(string[] lines, ConfigurationStore store, IAcronisTransport transport) =>
        new(store,
            () => transport,
            new StringReader(string.Join(Environment.NewLine, lines)),
            output,
            error,
            () => "typed-secret",
            new Trigger(
                () => transport,
                new NullPendingStartStore(),
                output: TextWriter.Null,
                error: TextWriter.Null));

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
}
