using AcronisBackupTrigger;
using System.Text.Json;

namespace AcronisBackupTrigger.Tests;

public sealed class ConfigurationStoreTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));

    [Fact]
    public void Save_then_load_returns_configuration_without_plaintext_secret()
    {
        var store = new ConfigurationStore(directory, new ReversingProtector());
        var expected = new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "client-secret");

        store.Save(expected);
        Assert.Equal(expected, store.Load());
        Assert.DoesNotContain("client-secret", File.ReadAllText(Path.Combine(directory, "configuration.dat")));
    }

    [Fact]
    public void Reset_removes_saved_configuration()
    {
        var store = new ConfigurationStore(directory, new ReversingProtector());
        store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "client-id", "client-secret"));

        store.Reset();

        Assert.Null(store.Load());
    }

    [Fact]
    public void Load_migrates_legacy_policy_and_resource_fields_to_target()
    {
        var legacy = """{"DataCenterUrl":"https://eu2.acronis.cloud","ClientId":"id","ClientSecret":"secret","PolicyId":"policy-1","PolicyName":"Daily","ResourceId":"resource-1","ResourceName":"SERVER-01"}""";
        var store = new ConfigurationStore(directory, new ReversingProtector());
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Path.Combine(directory, "configuration.dat"),
            System.Text.Encoding.UTF8.GetBytes(legacy).Reverse().ToArray());

        Assert.Equal(new ConfiguredTarget("policy-1", "Daily", "resource-1", "SERVER-01"), store.Load()!.Target);
    }

    [Fact]
    public void Save_writes_target_without_legacy_policy_resource_fields()
    {
        var store = new ConfigurationStore(directory, new ReversingProtector());
        store.Save(new TriggerConfiguration("https://eu2.acronis.cloud", "id", "secret",
            new ConfiguredTarget("policy-1", "Daily", "resource-1", "SERVER-01")));

        var storedBytes = File.ReadAllBytes(Path.Combine(directory, "configuration.dat"));
        var storedPlaintext = System.Text.Encoding.UTF8.GetString(storedBytes.Reverse().ToArray());
        using var doc = JsonDocument.Parse(storedPlaintext);
        var root = doc.RootElement;
        // Root must not contain PolicyId or ResourceId
        Assert.False(root.TryGetProperty("PolicyId", out _));
        Assert.False(root.TryGetProperty("ResourceId", out _));
        // Target must exist and have correct nested PolicyId and ResourceId values
        Assert.True(root.TryGetProperty("Target", out var targetElement));
        Assert.True(targetElement.TryGetProperty("PolicyId", out var nestedPolicyId));
        Assert.Equal("policy-1", nestedPolicyId.GetString());
        Assert.True(targetElement.TryGetProperty("ResourceId", out var nestedResourceId));
        Assert.Equal("resource-1", nestedResourceId.GetString());
    }

    public void Dispose()
    {
        if (Directory.Exists(directory))
            Directory.Delete(directory, recursive: true);
    }

    private sealed class ReversingProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => plaintext.Reverse().ToArray();
        public byte[] Unprotect(byte[] ciphertext) => ciphertext.Reverse().ToArray();
    }
}
