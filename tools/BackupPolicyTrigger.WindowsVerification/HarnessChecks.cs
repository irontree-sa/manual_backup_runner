using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using BackupPolicyTrigger;

namespace BackupPolicyTrigger.WindowsVerification;

/// <summary>
/// Emits only fixed check names, PASS/FAIL, and secret-free exception
/// categories. No fixture path, metadata value, identity SID, or semaphore
/// object name is ever written.
/// </summary>
internal sealed class HarnessReporter(TextWriter output)
{
    public void Report(string checkName, bool passed, string? category = null)
    {
        var status = passed ? "PASS" : "FAIL";
        output.WriteLine(category is null ? $"{checkName} {status}" : $"{checkName} {status} {category}");
    }

    public static string CategoryFor(Exception exception) => exception switch
    {
        SynchronizationMetadataException => "metadata",
        UntrustedNamedSemaphoreException => "semaphore",
        UnauthorizedAccessException => "access",
        IOException => "io",
        _ => "unexpected",
    };
}

internal static class HarnessChecks
{
    private const int ChildCount = 4;

    public static int RunParentSuite()
    {
        var reporter = new HarnessReporter(Console.Out);
        var failures = 0;

        using (var fixture = HarnessFixture.Create())
        {
            failures += RunCheck(reporter, "first-use", () => FirstUse(fixture));
            failures += RunCheck(reporter, "stable-read", () => StableRead(fixture));
            failures += RunCheck(reporter, "invalid-reparse", () => InvalidReparse(fixture));
            failures += RunCheck(reporter, "acl-matrix", () => AclMatrix(fixture));
            failures += RunCheck(reporter, "second-identity", () => SecondIdentity(fixture));
            failures += RunCheck(reporter, "current-operation-cleanup", () => CurrentOperationCleanup(fixture));
            failures += RunCheck(reporter, "publication-collision", () => PublicationCollision(fixture));
            failures += RunCheck(reporter, "contention", () => Contention(fixture));
            failures += RunCheck(reporter, "hostile-semaphore", () => HostileSemaphore(fixture));
            failures += RunCheck(reporter, "held-lock", () => HeldLock(fixture));
            failures += RunCheck(reporter, "dispatch-throw", () => DispatchThrow(fixture));
        }

        return failures == 0 ? ExitCodes.Success : 1;
    }

    public static int RunChildPublisher(string token)
    {
        var reporter = new HarnessReporter(Console.Out);
        var root = HarnessFixture.ResolveRoot(token);
        var directory = Path.Combine(root, HarnessFixture.ContentionDirectoryName);
        var identity = new ProtectedStorageIdentity(WindowsIdentity.GetCurrent().User!.Value);
        var store = new SynchronizationMetadataStore(directory);

        try
        {
            var metadata = store.ResolveOrCreateForValidatedStorage(identity);
            var existing = store.ResolveExisting(identity);
            var publishedNew = metadata.Identifier.Bytes.SequenceEqual(existing.Identifier.Bytes);
            reporter.Report("child-publish", true, publishedNew ? "PublishedNew" : "ReadExisting");
            return ExitCodes.Success;
        }
        catch (Exception exception)
        {
            reporter.Report("child-publish", false, HarnessReporter.CategoryFor(exception));
            return 1;
        }
    }

    private static int RunCheck(HarnessReporter reporter, string name, Action check)
    {
        try
        {
            check();
            reporter.Report(name, true);
            return 0;
        }
        catch (Exception exception)
        {
            reporter.Report(name, false, HarnessReporter.CategoryFor(exception));
            return 1;
        }
    }

    private static void FirstUse(HarnessFixture fixture)
    {
        var directory = fixture.CreateProtectedChild();
        var identity = new ProtectedStorageIdentity(WindowsIdentity.GetCurrent().User!.Value);
        var store = new SynchronizationMetadataStore(directory);
        var metadata = store.ResolveOrCreateForValidatedStorage(identity);
        if (metadata.Identifier.Bytes.Length != DeploymentIdentity.ByteLength)
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
    }

    private static void StableRead(HarnessFixture fixture)
    {
        var directory = fixture.CreateProtectedChild();
        var identity = new ProtectedStorageIdentity(WindowsIdentity.GetCurrent().User!.Value);
        var store = new SynchronizationMetadataStore(directory);
        var first = store.ResolveOrCreateForValidatedStorage(identity);
        var second = store.ResolveOrCreateForValidatedStorage(identity);
        if (!first.Identifier.Bytes.SequenceEqual(second.Identifier.Bytes))
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
    }

    private static void InvalidReparse(HarnessFixture fixture)
    {
        var directory = fixture.CreateProtectedChild();
        var identity = new ProtectedStorageIdentity(WindowsIdentity.GetCurrent().User!.Value);
        var store = new SynchronizationMetadataStore(directory);
        _ = store.ResolveOrCreateForValidatedStorage(identity);

        var published = Path.Combine(directory, "synchronization.json");
        var decoy = Path.Combine(directory, "decoy.json");
        File.WriteAllText(decoy, """{"Version":1,"AdministratorSid":"S-1-5-18","Identifier":"AAAAAAAAAAAAAAAAAAAAAA"}""");
        File.Delete(published);
        File.CreateSymbolicLink(published, decoy);

        try
        {
            store.ResolveExisting(identity);
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
        }
        catch (SynchronizationMetadataException)
        {
            // Expected: the reparse destination is rejected.
        }
    }

    private static void AclMatrix(HarnessFixture fixture)
    {
        var directory = fixture.CreateProtectedChild();
        var identity = new ProtectedStorageIdentity(WindowsIdentity.GetCurrent().User!.Value);
        var store = new SynchronizationMetadataStore(directory);
        _ = store.ResolveOrCreateForValidatedStorage(identity);

        var published = Path.Combine(directory, "synchronization.json");
        var security = new FileInfo(published).GetAccessControl();
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || owner.Value != identity.AdministratorSid)
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
        if (!security.AreAccessRulesProtected)
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
    }

    private static void SecondIdentity(HarnessFixture fixture)
    {
        var directory = fixture.CreateProtectedChild();
        var identity = new ProtectedStorageIdentity(WindowsIdentity.GetCurrent().User!.Value);
        var store = new SynchronizationMetadataStore(directory);
        _ = store.ResolveOrCreateForValidatedStorage(identity);

        try
        {
            store.ResolveExisting(new ProtectedStorageIdentity("S-1-5-32-544"));
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
        }
        catch (SynchronizationMetadataException)
        {
            // Expected: a second administrator identity is rejected.
        }
    }

    private static void CurrentOperationCleanup(HarnessFixture fixture)
    {
        var directory = fixture.CreateProtectedChild();
        var identity = new ProtectedStorageIdentity(WindowsIdentity.GetCurrent().User!.Value);
        var store = new SynchronizationMetadataStore(directory);
        _ = store.ResolveOrCreateForValidatedStorage(identity);

        // A failed publication must leave no temporary behind.
        if (Directory.EnumerateFiles(directory, ".synchronization.*.tmp").Any())
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
    }

    private static void PublicationCollision(HarnessFixture fixture)
    {
        var directory = fixture.CreateProtectedChild();
        var identity = new ProtectedStorageIdentity(WindowsIdentity.GetCurrent().User!.Value);
        var store = new SynchronizationMetadataStore(directory);
        _ = store.ResolveOrCreateForValidatedStorage(identity);

        // A pre-existing destination must be read, not overwritten.
        var existing = store.ResolveExisting(identity);
        var again = store.ResolveOrCreateForValidatedStorage(identity);
        if (!existing.Identifier.Bytes.SequenceEqual(again.Identifier.Bytes))
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
    }

    private static void Contention(HarnessFixture fixture)
    {
        var directory = fixture.CreateProtectedChild(HarnessFixture.ContentionDirectoryName);
        var identity = new ProtectedStorageIdentity(WindowsIdentity.GetCurrent().User!.Value);

        var executable = Environment.ProcessPath
            ?? throw new InvalidOperationException("The harness executable path is unavailable.");
        var results = new List<string>();
        var processes = new List<Process>();

        for (var i = 0; i < ChildCount; i++)
        {
            var start = new ProcessStartInfo
            {
                FileName = executable,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            start.ArgumentList.Add("--child-publish");
            start.ArgumentList.Add(fixture.Token);
            var process = Process.Start(start)
                ?? throw new InvalidOperationException("A contention child could not be started.");
            processes.Add(process);
        }

        foreach (var process in processes)
        {
            process.WaitForExit();
            var line = process.StandardOutput.ReadLine()?.Trim();
            if (line is not null) results.Add(line);
            if (process.ExitCode != ExitCodes.Success)
                throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
        }

        var publishedNew = results.Count(line => line.EndsWith("PublishedNew", StringComparison.Ordinal));
        var readExisting = results.Count(line => line.EndsWith("ReadExisting", StringComparison.Ordinal));
        if (publishedNew != 1 || readExisting != ChildCount - 1)
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");

        var store = new SynchronizationMetadataStore(directory);
        _ = store.ResolveExisting(identity);
    }

    private static void HostileSemaphore(HarnessFixture fixture)
    {
        var directory = fixture.CreateProtectedChild();
        var identity = new ProtectedStorageIdentity(WindowsIdentity.GetCurrent().User!.Value);
        var store = new SynchronizationMetadataStore(directory);
        var metadata = store.ResolveOrCreateForValidatedStorage(identity);

        // A hostile descriptor (extra ACE) must be rejected before dispatch.
        var hostile = new NamedSemaphoreDescriptor(
            IsDaclProtected: true,
            Aces:
            [
                new("S-1-5-18", AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None, IsInherited: false),
                new(identity.AdministratorSid, AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None, IsInherited: false),
                new("S-1-5-32-545", AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None, IsInherited: false),
            ]);
        var hostileApi = new FixedDescriptorSemaphoreApi(hostile, createdNew: false);
        var hostileFactory = new NamedSemaphoreFactory(hostileApi);

        var gate = new StartupSynchronizationGate();
        var exit = gate.ExecuteAsync(
            Request(directory, metadata, hostileFactory),
            () => throw new InvalidOperationException("dispatch must not run"),
            TextWriter.Null).GetAwaiter().GetResult();

        if (exit != ExitCodes.InternalError)
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
    }

    private static void HeldLock(HarnessFixture fixture)
    {
        var directory = fixture.CreateProtectedChild();
        var identity = new ProtectedStorageIdentity(WindowsIdentity.GetCurrent().User!.Value);
        var store = new SynchronizationMetadataStore(directory);
        var metadata = store.ResolveOrCreateForValidatedStorage(identity);

        var trusted = new NamedSemaphoreDescriptor(
            IsDaclProtected: true,
            Aces:
            [
                new("S-1-5-18", AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None, IsInherited: false),
                new(identity.AdministratorSid, AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None, IsInherited: false),
            ]);
        var api = new FixedDescriptorSemaphoreApi(trusted, createdNew: true);
        var factory = new NamedSemaphoreFactory(api);

        // Hold the trusted machine semaphore, then assert exit 11 / no dispatch.
        using (var held = factory.OpenTrusted(metadata, SynchronizationLockPurpose.MachineRun))
        {
            var gate = new StartupSynchronizationGate();
            var exit = gate.ExecuteAsync(
                Request(directory, metadata, factory),
                () => throw new InvalidOperationException("dispatch must not run"),
                TextWriter.Null).GetAwaiter().GetResult();

            if (exit != ExitCodes.AlreadyRunning)
                throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
        }
    }

    private static void DispatchThrow(HarnessFixture fixture)
    {
        var directory = fixture.CreateProtectedChild();
        var identity = new ProtectedStorageIdentity(WindowsIdentity.GetCurrent().User!.Value);
        var store = new SynchronizationMetadataStore(directory);
        var metadata = store.ResolveOrCreateForValidatedStorage(identity);

        var trusted = new NamedSemaphoreDescriptor(
            IsDaclProtected: true,
            Aces:
            [
                new("S-1-5-18", AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None, IsInherited: false),
                new(identity.AdministratorSid, AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None, IsInherited: false),
            ]);
        var api = new FixedDescriptorSemaphoreApi(trusted, createdNew: true);
        var factory = new NamedSemaphoreFactory(api);

        var gate = new StartupSynchronizationGate();
        try
        {
            gate.ExecuteAsync(
                Request(directory, metadata, factory),
                () => throw new InvalidOperationException("dispatch failed"),
                TextWriter.Null).GetAwaiter().GetResult();
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
        }
        catch (InvalidOperationException)
        {
            // Expected: the dispatch throw propagates after the lock is released.
        }

        // The semaphore must be released and disposed: a fresh acquisition succeeds.
        using var reacquired = factory.OpenTrusted(metadata, SynchronizationLockPurpose.MachineRun);
        if (!reacquired.WaitOne(TimeSpan.Zero))
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
    }

    private static StartupSynchronizationRequest Request(
        string directory,
        SynchronizationMetadata metadata,
        NamedSemaphoreFactory factory) => new(
            directory,
            SetupRequested: false,
            TimeSpan.Zero,
            new ConfigurationStoreAdapter(directory),
            new FixedMetadataAdapter(metadata),
            new FixedSemaphoreAdapter(factory),
            new ElevatedAdapter(),
            new CurrentAdministratorIdentity());

    private sealed class FixedMetadataAdapter(SynchronizationMetadata metadata) : ISynchronizationMetadataAdapter
    {
        public SynchronizationMetadata ResolveOrCreateForValidatedStorage(ProtectedStorageIdentity identity) => metadata;
    }

    private sealed class FixedSemaphoreAdapter(NamedSemaphoreFactory factory) : INamedSemaphoreAdapter
    {
        public ISynchronizationLock OpenTrusted(SynchronizationMetadata metadata) =>
            new SemaphoreLock(factory.OpenTrusted(metadata, SynchronizationLockPurpose.MachineRun));
    }

    private sealed class ElevatedAdapter : IAdministratorElevationAdapter
    {
        public bool IsElevated => true;
    }

    private sealed class CurrentAdministratorIdentity : IConfigurationAdministratorIdentity
    {
        public string? CurrentAdministratorSid => WindowsIdentity.GetCurrent().User?.Value;
    }

    private sealed class FixedDescriptorSemaphoreApi(NamedSemaphoreDescriptor descriptor, bool createdNew) : INamedSemaphoreApi
    {
        public Semaphore Create(string name, NamedSemaphoreDescriptor security, out bool createdNewFlag)
        {
            createdNewFlag = createdNew;
            return new Semaphore(1, 1);
        }

        public NamedSemaphoreDescriptor GetSecurity(Semaphore semaphore) => descriptor;
    }
}
