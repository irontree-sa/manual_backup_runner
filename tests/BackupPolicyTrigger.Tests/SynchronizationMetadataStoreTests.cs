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
        File.WriteAllText(Path.Combine(directory, "synchronization.json"), "{}");
        var store = new SynchronizationMetadataStore(directory);

        Assert.Throws<SynchronizationMetadataException>(() =>
            store.ResolveOrCreateForValidatedStorage(new ProtectedStorageIdentity("S-1-5-18")));

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
        var identity = new ProtectedStorageIdentity("S-1-5-18");
        var api = new RecordingMetadataFileApi(directory) { RejectPostWriteValidation = true };
        var store = new SynchronizationMetadataStore(directory, api);

        Assert.Throws<SynchronizationMetadataException>(() =>
            store.ResolveOrCreateForValidatedStorage(identity));
        Assert.True(api.ValidatedAfterFlushAndClose);
        Assert.False(File.Exists(Path.Combine(directory, "synchronization.json")));
    }

    [Fact]
    public void Current_operation_cleanup_validates_owner_and_dacl_before_disposition()
    {
        Directory.CreateDirectory(directory);
        var identity = new ProtectedStorageIdentity("S-1-5-18");
        var api = new RecordingMetadataFileApi(directory);
        var store = new SynchronizationMetadataStore(directory, api);

        api.CauseNoReplaceCollision();
        Assert.Throws<SynchronizationMetadataException>(() =>
            store.ResolveOrCreateForValidatedStorage(identity));
        Assert.True(api.ValidatedCleanupOwnerAndDacl);
        Assert.True(api.DispositionWasRequestedOnlyForCurrentTemporary);
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
    /// Deterministic file-operation adapter used only by these tests. It records
    /// whether post-write validation ran after flush-and-close and whether cleanup
    /// validated owner/DACL before requesting disposition of only the current
    /// operation's temporary path.
    /// </summary>
    private sealed class RecordingMetadataFileApi : IMetadataFileApi
    {
        private readonly string directory;
        private string? cleanupPath;
        private string? dispositionPath;

        public RecordingMetadataFileApi(string directory) => this.directory = directory;

        public bool RejectPostWriteValidation { get; set; }
        public bool ValidatedAfterFlushAndClose { get; private set; }
        public bool ValidatedCleanupOwnerAndDacl { get; private set; }
        public bool DispositionWasRequestedOnlyForCurrentTemporary { get; private set; }

        private bool createCollisionOnValidate;

        public void CauseNoReplaceCollision() => createCollisionOnValidate = true;

        public void ValidateForPublication(string path, string administratorSid)
        {
            ValidatedAfterFlushAndClose = true;
            if (createCollisionOnValidate)
                File.WriteAllText(Path.Combine(directory, "synchronization.json"), "{}");
            if (RejectPostWriteValidation)
                throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
        }

        public void ValidateForCleanup(string path, string administratorSid)
        {
            ValidatedCleanupOwnerAndDacl = true;
            cleanupPath = path;
        }

        public void RequestDisposition(string path)
        {
            dispositionPath = path;
            DispositionWasRequestedOnlyForCurrentTemporary =
                string.Equals(cleanupPath, path, StringComparison.Ordinal)
                && Path.GetFileName(path).StartsWith(".synchronization.", StringComparison.Ordinal)
                && path.EndsWith(".tmp", StringComparison.Ordinal);
        }
    }
}
