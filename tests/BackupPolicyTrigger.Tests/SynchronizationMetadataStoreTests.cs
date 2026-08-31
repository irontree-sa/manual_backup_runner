using System.Security.AccessControl;
using BackupPolicyTrigger;

namespace BackupPolicyTrigger.Tests;

public sealed class SynchronizationMetadataStoreTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));

    [Fact]
    public void ResolveOrCreate_publishes_a_stable_128_bit_deployment_identity()
    {
        var identity = new ProtectedStorageIdentity("S-1-5-18");
        Directory.CreateDirectory(directory);
        var store = new SynchronizationMetadataStore(directory);

        var first = store.ResolveOrCreateForValidatedStorage(identity);
        var second = store.ResolveOrCreateForValidatedStorage(identity);

        Assert.True(first.Identifier.Bytes.SequenceEqual(second.Identifier.Bytes));
        Assert.Equal(DeploymentIdentity.ByteLength, first.Identifier.Bytes.Length);
        var contents = File.ReadAllText(Path.Combine(directory, "synchronization.json"));
        Assert.DoesNotContain('=', contents);
    }

    [Fact]
    public async Task Concurrent_first_use_returns_one_published_identity()
    {
        Directory.CreateDirectory(directory);
        var identity = new ProtectedStorageIdentity("S-1-5-18");
        var identities = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ =>
            Task.Run(() => new SynchronizationMetadataStore(directory).ResolveOrCreateForValidatedStorage(identity))));

        Assert.All(identities, metadata =>
            Assert.True(identities[0].Identifier.Bytes.SequenceEqual(metadata.Identifier.Bytes)));
        Assert.Single(Directory.EnumerateFiles(directory, "synchronization.json"));
    }

    [Fact]
    public void Existing_metadata_rejects_a_second_administrator()
    {
        Directory.CreateDirectory(directory);
        var store = new SynchronizationMetadataStore(directory);
        _ = store.ResolveOrCreateForValidatedStorage(new ProtectedStorageIdentity("S-1-5-18"));

        Assert.Throws<SynchronizationMetadataException>(() =>
            store.ResolveExisting(new ProtectedStorageIdentity("S-1-5-32-544")));
    }

    [Fact]
    public void Failed_publication_cleans_its_temporary_metadata()
    {
        Directory.CreateDirectory(directory);
        var identity = new ProtectedStorageIdentity("S-1-5-32-544");
        // Force a failure after the temporary has been created and written: the
        // post-write validation rejects the temporary, so cleanup must dispose the
        // exact generated `.tmp` file (not an obsolete `.new`).
        var api = new RecordingMetadataFileApi(directory) { RejectPostWriteValidation = true };
        var store = new SynchronizationMetadataStore(directory, api);

        Assert.Throws<SynchronizationMetadataException>(() =>
            store.ResolveOrCreateForValidatedStorage(identity));

        Assert.Empty(Directory.EnumerateFiles(directory, ".synchronization.*.tmp"));
        Assert.Empty(Directory.EnumerateFiles(directory, ".synchronization.*.new"));
    }

    [Fact]
    public void Reparse_metadata_destination_is_rejected()
    {
        Directory.CreateDirectory(directory);
        var target = Path.Combine(directory, "target.json");
        File.WriteAllText(target, """{"Version":1,"AdministratorSid":"S-1-5-18","Identifier":"AAAAAAAAAAAAAAAAAAAAAA"}""");
        File.CreateSymbolicLink(Path.Combine(directory, "synchronization.json"), target);

        Assert.Throws<SynchronizationMetadataException>(() =>
            new SynchronizationMetadataStore(directory).ResolveExisting(new ProtectedStorageIdentity("S-1-5-18")));
    }

    [Fact]
    public void Publication_rejects_temporary_file_when_post_write_acl_validation_fails()
    {
        Directory.CreateDirectory(directory);
        var identity = new ProtectedStorageIdentity("S-1-5-32-544");
        var api = new RecordingMetadataFileApi(directory) { RejectPostWriteValidation = true };
        var store = new SynchronizationMetadataStore(directory, api);

        Assert.Throws<SynchronizationMetadataException>(() =>
            store.ResolveOrCreateForValidatedStorage(identity));

        // The temporary was observed, and the observation saw the complete
        // serialized metadata bytes — proving the writer flushed and closed before
        // validation ran.
        Assert.Contains(api.Events, e => e.StartsWith("observe:", StringComparison.Ordinal));
        Assert.NotEmpty(api.ObservedContents);
        var bytes = api.ObservedContents[0];
        Assert.True(bytes.Length > 0, "the temporary must contain the serialized metadata");
        using var document = System.Text.Json.JsonDocument.Parse(bytes);
        Assert.True(SynchronizationMetadataStore.HasExactSchema(document.RootElement));
        Assert.False(File.Exists(Path.Combine(directory, "synchronization.json")));
    }

    [Fact]
    public void Current_operation_cleanup_validates_owner_and_dacl_before_disposition()
    {
        Directory.CreateDirectory(directory);
        var identity = new ProtectedStorageIdentity("S-1-5-32-544");
        var api = new RecordingMetadataFileApi(directory) { CauseNoReplaceCollision = true };
        var store = new SynchronizationMetadataStore(directory, api);

        Assert.Throws<SynchronizationMetadataException>(() =>
            store.ResolveOrCreateForValidatedStorage(identity));

        // Exactly two observations: the publication validation and the cleanup. The
        // cleanup must observe, dispose, and close the exact same generated temporary
        // filename — never a decoy.
        var events = api.Events.ToList();
        var observes = events.Where(e => e.StartsWith("observe:", StringComparison.Ordinal)).ToList();
        Assert.Equal(2, observes.Count);
        var temporary = observes[0]["observe:".Length..];
        Assert.Equal($"observe:{temporary}", observes[1]);
        Assert.Contains($"dispose:{temporary}", events);
        Assert.Contains($"close:{temporary}", events);

        var observe = events.FindIndex(e => e == $"observe:{temporary}");
        var dispose = events.FindIndex(e => e == $"dispose:{temporary}");
        var close = events.FindLastIndex(e => e == $"close:{temporary}");
        Assert.True(observe >= 0, "cleanup must observe the temporary");
        Assert.True(dispose > observe, "disposition must follow observation");
        Assert.True(close > dispose, "the observed handle must close after disposition");
    }

    [Fact]
    public void Cleanup_skips_disposition_when_owner_does_not_match()
    {
        Directory.CreateDirectory(directory);
        var identity = new ProtectedStorageIdentity("S-1-5-32-544");
        var api = new RecordingMetadataFileApi(directory)
        {
            CauseNoReplaceCollision = true,
            OwnerSid = "S-1-5-21-1234567890-123456789-123456789-500",
        };
        var store = new SynchronizationMetadataStore(directory, api);

        Assert.Throws<SynchronizationMetadataException>(() =>
            store.ResolveOrCreateForValidatedStorage(identity));
        Assert.DoesNotContain(api.Events, e => e.StartsWith("dispose:", StringComparison.Ordinal));
    }

    [Fact]
    public void Cleanup_skips_disposition_when_dacl_is_not_protected()
    {
        Directory.CreateDirectory(directory);
        var identity = new ProtectedStorageIdentity("S-1-5-32-544");
        var api = new RecordingMetadataFileApi(directory)
        {
            CauseNoReplaceCollision = true,
            IsDaclProtected = false,
        };
        var store = new SynchronizationMetadataStore(directory, api);

        Assert.Throws<SynchronizationMetadataException>(() =>
            store.ResolveOrCreateForValidatedStorage(identity));
        Assert.DoesNotContain(api.Events, e => e.StartsWith("dispose:", StringComparison.Ordinal));
    }

    [Fact]
    public void Cleanup_skips_disposition_when_rules_are_not_exact()
    {
        Directory.CreateDirectory(directory);
        var identity = new ProtectedStorageIdentity("S-1-5-32-544");
        var api = new RecordingMetadataFileApi(directory)
        {
            CauseNoReplaceCollision = true,
            AccessRules =
            [
                new("S-1-5-18", AccessControlType.Allow, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, IsInherited: false),
                new("S-1-5-32-544", AccessControlType.Allow, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, IsInherited: false),
                new("S-1-5-32-545", AccessControlType.Allow, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, IsInherited: false),
            ],
        };
        var store = new SynchronizationMetadataStore(directory, api);

        Assert.Throws<SynchronizationMetadataException>(() =>
            store.ResolveOrCreateForValidatedStorage(identity));
        Assert.DoesNotContain(api.Events, e => e.StartsWith("dispose:", StringComparison.Ordinal));
    }

    [Fact]
    public void Cleanup_tolerates_current_temporary_disappearing()
    {
        Directory.CreateDirectory(directory);
        var identity = new ProtectedStorageIdentity("S-1-5-32-544");
        var api = new RecordingMetadataFileApi(directory)
        {
            CauseNoReplaceCollision = true,
            DisappearBeforeCleanup = true,
        };
        var store = new SynchronizationMetadataStore(directory, api);

        Assert.Throws<SynchronizationMetadataException>(() =>
            store.ResolveOrCreateForValidatedStorage(identity));
        Assert.DoesNotContain(api.Events, e => e.StartsWith("dispose:", StringComparison.Ordinal));
    }

    [Fact]
    public void Cleanup_skips_disposition_when_a_deny_rule_is_present()
    {
        Directory.CreateDirectory(directory);
        var identity = new ProtectedStorageIdentity("S-1-5-32-544");
        var api = new RecordingMetadataFileApi(directory)
        {
            CauseNoReplaceCollision = true,
            AccessRules =
            [
                new("S-1-5-18", AccessControlType.Allow, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, IsInherited: false),
                new("S-1-5-32-544", AccessControlType.Allow, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, IsInherited: false),
                new("S-1-5-32-545", AccessControlType.Deny, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, IsInherited: false),
            ],
        };
        var store = new SynchronizationMetadataStore(directory, api);

        Assert.Throws<SynchronizationMetadataException>(() =>
            store.ResolveOrCreateForValidatedStorage(identity));
        Assert.DoesNotContain(api.Events, e => e.StartsWith("dispose:", StringComparison.Ordinal));
    }

    [Fact]
    public void Cleanup_skips_disposition_when_rights_are_altered()
    {
        Directory.CreateDirectory(directory);
        var identity = new ProtectedStorageIdentity("S-1-5-32-544");
        var api = new RecordingMetadataFileApi(directory)
        {
            CauseNoReplaceCollision = true,
            AccessRules =
            [
                new("S-1-5-18", AccessControlType.Allow, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, IsInherited: false),
                new("S-1-5-32-544", AccessControlType.Allow, FileSystemRights.Read, InheritanceFlags.None, PropagationFlags.None, IsInherited: false),
            ],
        };
        var store = new SynchronizationMetadataStore(directory, api);

        Assert.Throws<SynchronizationMetadataException>(() =>
            store.ResolveOrCreateForValidatedStorage(identity));
        Assert.DoesNotContain(api.Events, e => e.StartsWith("dispose:", StringComparison.Ordinal));
    }

    [Fact]
    public void Cleanup_skips_disposition_when_a_rule_is_inherited()
    {
        Directory.CreateDirectory(directory);
        var identity = new ProtectedStorageIdentity("S-1-5-32-544");
        var api = new RecordingMetadataFileApi(directory)
        {
            CauseNoReplaceCollision = true,
            AccessRules =
            [
                new("S-1-5-18", AccessControlType.Allow, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, IsInherited: false),
                new("S-1-5-32-544", AccessControlType.Allow, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, IsInherited: true),
            ],
        };
        var store = new SynchronizationMetadataStore(directory, api);

        Assert.Throws<SynchronizationMetadataException>(() =>
            store.ResolveOrCreateForValidatedStorage(identity));
        Assert.DoesNotContain(api.Events, e => e.StartsWith("dispose:", StringComparison.Ordinal));
    }

    [Fact]
    public void Cleanup_unlinks_reparse_point_without_traversing_external_target()
    {
        Directory.CreateDirectory(directory);
        var external = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(external);
        var sentinel = Path.Combine(external, "sentinel.txt");
        File.WriteAllText(sentinel, "keep");
        try
        {
            File.CreateSymbolicLink(Path.Combine(directory, "external-link"), external);

            // Fixture teardown must unlink the reparse point, never traverse into
            // the external directory it points at.
            Directory.Delete(directory, recursive: true);

            Assert.False(Directory.Exists(directory));
            Assert.True(File.Exists(sentinel), "the external target must survive reparse-point unlink");
        }
        finally
        {
            if (Directory.Exists(external)) Directory.Delete(external, recursive: true);
        }
    }

    [Theory]
    [InlineData("S-1-5-18", true)]
    [InlineData("S-1-5-32-544", true)]
    [InlineData("S-1-5", false)]
    [InlineData("S-1-not-a-number-18", false)]
    public void Metadata_requires_a_well_formed_administrator_sid(string sid, bool expected)
    {
        Assert.Equal(expected, SynchronizationMetadataStore.IsValidAdministratorSid(sid));
    }

    [Theory]
    [InlineData("""{"Version":1,"AdministratorSid":"S-1-5-18","Identifier":"AAAAAAAAAAAAAAAAAAAAAA"}""", true)]
    [InlineData("""{"Version":1,"AdministratorSid":"S-1-5-18","Identifier":"AAAAAAAAAAAAAAAAAAAAAA","Unexpected":true}""", false)]
    [InlineData("""{"Version":1,"AdministratorSid":"S-1-5-18"}""", false)]
    public void Metadata_schema_requires_exactly_the_three_declared_fields(string json, bool expected)
    {
        using var document = System.Text.Json.JsonDocument.Parse(json);

        Assert.Equal(expected, SynchronizationMetadataStore.HasExactSchema(document.RootElement));
    }

    [Theory]
    [InlineData(2, true)]
    [InlineData(3, true)]
    [InlineData(5, false)]
    public void Native_open_errors_preserve_first_use_creation(int error, bool expected)
    {
        Assert.Equal(expected, SynchronizationMetadataStore.IsMissingPathError(error));
    }

    public void Dispose()
    {
        if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }

    /// <summary>
    /// Deterministic file-operation adapter used only by these tests. It records an
    /// ordered event trace and reports configurable security facts so the store's
    /// owner/protection/rule predicates and disposition ordering can be observed
    /// without constructing Windows-only ACL objects.
    /// </summary>
    private sealed class RecordingMetadataFileApi : IMetadataFileApi
    {
        private readonly string directory;
        private readonly List<string> events = new();
        private readonly List<byte[]> observedContents = new();

        public RecordingMetadataFileApi(string directory) => this.directory = directory;

        public string? OwnerSid { get; set; } = "S-1-5-32-544";
        public bool IsDaclProtected { get; set; } = true;
        public IReadOnlyList<MetadataAccessRule> AccessRules { get; set; } = ExactRules;
        public bool RejectPostWriteValidation { get; set; }
        public bool CauseNoReplaceCollision { get; set; }
        public bool DisappearBeforeCleanup { get; set; }

        public IReadOnlyList<string> Events => events;
        public IReadOnlyList<byte[]> ObservedContents => observedContents;

        private static readonly IReadOnlyList<MetadataAccessRule> ExactRules =
        [
            new("S-1-5-18", AccessControlType.Allow, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, IsInherited: false),
            new("S-1-5-32-544", AccessControlType.Allow, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, IsInherited: false),
        ];

        public IMetadataObservation Observe(string path)
        {
            events.Add($"observe:{Path.GetFileName(path)}");
            // Prove the writer flushed and closed: reopen the temporary exclusively
            // (FileShare.None) and capture its complete bytes. A still-open writer
            // would fail this open, and a partial write would yield truncated bytes.
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None))
            using (var buffer = new MemoryStream())
            {
                stream.CopyTo(buffer);
                observedContents.Add(buffer.ToArray());
            }
            if (CauseNoReplaceCollision)
                File.WriteAllText(Path.Combine(directory, "synchronization.json"), "{}");
            if (RejectPostWriteValidation)
            {
                RejectPostWriteValidation = false;
                throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
            }
            if (DisappearBeforeCleanup && events.Count(e => e.StartsWith("observe:", StringComparison.Ordinal)) > 1)
                throw new FileNotFoundException("Synchronization metadata does not exist.", path);
            return new RecordingObservation(this, path);
        }

        private sealed class RecordingObservation(RecordingMetadataFileApi owner, string path) : IMetadataObservation
        {
            public string? OwnerSid => owner.OwnerSid;
            public bool IsDaclProtected => owner.IsDaclProtected;
            public IReadOnlyList<MetadataAccessRule> AccessRules => owner.AccessRules;

            public void RequestDisposition()
            {
                owner.events.Add($"dispose:{Path.GetFileName(path)}");
                File.Delete(path);
            }

            public void Dispose() => owner.events.Add($"close:{Path.GetFileName(path)}");
        }
    }
}
