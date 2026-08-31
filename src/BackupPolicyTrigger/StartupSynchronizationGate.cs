using System.Runtime.Versioning;
using System.Security.Principal;

namespace BackupPolicyTrigger;

internal interface IAdministratorElevationAdapter
{
    bool IsElevated { get; }
}

internal sealed record StartupSynchronizationRequest(
    string StoragePath,
    bool SetupRequested,
    TimeSpan LockTimeout,
    IProtectedStorageAdapter Storage,
    ISynchronizationMetadataAdapter Metadata,
    INamedSemaphoreAdapter Semaphores,
    IAdministratorElevationAdapter Elevation,
    IConfigurationAdministratorIdentity AdministratorIdentity);

internal interface IProtectedStorageAdapter
{
    ProtectedStorageIdentity? EnsureProtectedStorageIdentity();
    ProtectedStorageIdentity ValidateProtectedStorage();
}

internal interface ISynchronizationMetadataAdapter
{
    SynchronizationMetadata ResolveOrCreateForValidatedStorage(ProtectedStorageIdentity identity);
}

internal interface ISynchronizationLock : IDisposable
{
    bool WaitOne(TimeSpan timeout);
    void Release();
}

internal interface INamedSemaphoreAdapter
{
    ISynchronizationLock OpenTrusted(SynchronizationMetadata metadata);
}

internal interface IConfigurationAdministratorIdentity
{
    string? CurrentAdministratorSid { get; }
}

/// <summary>
/// Deep startup orchestration: setup elevation, protected-storage validation,
/// metadata resolution, trusted-semaphore validation, bounded acquisition, and
/// dispatch ordering. The gate owns and disposes the semaphore in every path,
/// including when dispatch throws. It constructs no transport, trigger, pending
/// marker, or command host; those are created only inside the dispatch callback.
/// </summary>
internal sealed class StartupSynchronizationGate
{
    public async Task<int> ExecuteAsync(
        StartupSynchronizationRequest request,
        Func<Task<int>> dispatch,
        TextWriter error)
    {
        if (request.SetupRequested && !request.Elevation.IsElevated)
            return ExitCodes.AdministratorRequired;

        ISynchronizationLock machineLock;
        try
        {
            var identity = request.SetupRequested
                ? request.Storage.EnsureProtectedStorageIdentity()
                : request.Storage.ValidateProtectedStorage();
            if (identity is null)
                throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");

            if (request.SetupRequested
                && request.AdministratorIdentity.CurrentAdministratorSid is { } currentSid
                && !string.Equals(identity.AdministratorSid, currentSid, StringComparison.Ordinal))
                throw new SynchronizationMetadataException("Protected storage belongs to a different Configuration administrator.");

            var metadata = request.Metadata.ResolveOrCreateForValidatedStorage(identity);
            machineLock = request.Semaphores.OpenTrusted(metadata);
        }
        catch (Exception exception) when (exception is SynchronizationMetadataException
            or UntrustedNamedSemaphoreException
            or IOException
            or UnauthorizedAccessException
            or WaitHandleCannotBeOpenedException)
        {
            error.WriteLine("Machine synchronization security could not be validated. No backup was requested.");
            return ExitCodes.InternalError;
        }

        using (machineLock)
        {
            if (!machineLock.WaitOne(request.LockTimeout))
            {
                error.WriteLine("Another Backup Policy Trigger run is in progress on this machine.");
                return ExitCodes.AlreadyRunning;
            }

            try
            {
                return await dispatch();
            }
            finally
            {
                machineLock.Release();
            }
        }
    }
}

internal sealed class ConfigurationStoreAdapter : IProtectedStorageAdapter
{
    private readonly ConfigurationStore store;
    private readonly string directory;

    public ConfigurationStoreAdapter(string directory)
    {
        this.directory = directory;
        this.store = new ConfigurationStore(directory, new WindowsDpapiProtector());
    }

    public ProtectedStorageIdentity? EnsureProtectedStorageIdentity() => store.EnsureProtectedStorageIdentity();

    public ProtectedStorageIdentity ValidateProtectedStorage() =>
        ConfigurationStore.ValidateProtectedStorage(directory);
}

internal sealed class SynchronizationMetadataStoreAdapter : ISynchronizationMetadataAdapter
{
    private readonly SynchronizationMetadataStore store;

    public SynchronizationMetadataStoreAdapter(string directory) => store = new SynchronizationMetadataStore(directory);

    public SynchronizationMetadata ResolveOrCreateForValidatedStorage(ProtectedStorageIdentity identity) =>
        store.ResolveOrCreateForValidatedStorage(identity);
}

internal sealed class NamedSemaphoreFactoryAdapter : INamedSemaphoreAdapter
{
    private readonly NamedSemaphoreFactory factory = new();

    public ISynchronizationLock OpenTrusted(SynchronizationMetadata metadata) =>
        new SemaphoreLock(factory.OpenTrusted(metadata, SynchronizationLockPurpose.MachineRun));
}

internal sealed class SemaphoreLock : ISynchronizationLock
{
    private readonly Semaphore semaphore;

    public SemaphoreLock(Semaphore semaphore) => this.semaphore = semaphore;

    public bool WaitOne(TimeSpan timeout) => semaphore.WaitOne(timeout);

    public void Release() => semaphore.Release();

    public void Dispose() => semaphore.Dispose();
}

[SupportedOSPlatform("windows")]
internal sealed class WindowsConfigurationAdministratorIdentity : IConfigurationAdministratorIdentity
{
    public string? CurrentAdministratorSid => WindowsIdentity.GetCurrent().User?.Value;
}
