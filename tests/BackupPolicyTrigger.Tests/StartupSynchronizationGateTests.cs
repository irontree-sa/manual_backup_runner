using BackupPolicyTrigger;

namespace BackupPolicyTrigger.Tests;

public sealed class StartupSynchronizationGateTests
{
    private readonly StartupSynchronizationGate gate = new();
    private readonly StringWriter error = new();
    private bool dispatched;

    [Fact]
    public async Task Unelevated_setup_returns_administrator_required_without_dependencies()
    {
        var dependencies = new RecordingSynchronizationDependencies { IsElevated = false };
        var exit = await gate.ExecuteAsync(dependencies.SetupRequest(), Dispatch, error);

        Assert.Equal(ExitCodes.AdministratorRequired, exit);
        Assert.False(dependencies.StorageWasRead);
        Assert.False(dispatched);
    }

    [Theory]
    [InlineData(SynchronizationFailure.Metadata)]
    [InlineData(SynchronizationFailure.Semaphore)]
    public async Task Security_failure_returns_exit_8_before_dispatch(SynchronizationFailure failure)
    {
        var dependencies = new RecordingSynchronizationDependencies { Failure = failure };
        var exit = await gate.ExecuteAsync(dependencies.RunRequest(), Dispatch, error);

        Assert.Equal(ExitCodes.InternalError, exit);
        Assert.False(dispatched);
        Assert.Equal("Machine synchronization security could not be validated. No backup was requested." + Environment.NewLine, error.ToString());
    }

    [Fact]
    public async Task Held_lock_returns_exit_11_without_dispatch()
    {
        var heldLockDependencies = new RecordingSynchronizationDependencies { HoldLock = true };
        var exit = await gate.ExecuteAsync(heldLockDependencies.RunRequest(), Dispatch, error);

        Assert.Equal(ExitCodes.AlreadyRunning, exit);
        Assert.False(dispatched);
    }

    [Fact]
    public async Task Dispatch_exception_releases_and_disposes_semaphore()
    {
        var validDependencies = new RecordingSynchronizationDependencies();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            gate.ExecuteAsync(validDependencies.RunRequest(), ThrowingDispatch, error));
        Assert.True(validDependencies.SemaphoreReleased);
        Assert.True(validDependencies.SemaphoreDisposed);
    }

    [Fact]
    public async Task Successful_acquisition_dispatches_and_returns_result()
    {
        var dependencies = new RecordingSynchronizationDependencies();
        var exit = await gate.ExecuteAsync(dependencies.RunRequest(), Dispatch, error);

        Assert.Equal(ExitCodes.Success, exit);
        Assert.True(dispatched);
        Assert.True(dependencies.SemaphoreReleased);
        Assert.True(dependencies.SemaphoreDisposed);
    }

    private Task<int> Dispatch()
    {
        dispatched = true;
        return Task.FromResult(ExitCodes.Success);
    }

    private static Task<int> ThrowingDispatch() => throw new InvalidOperationException("dispatch failed");

    public enum SynchronizationFailure
    {
        None,
        Metadata,
        Semaphore,
    }

    private sealed class RecordingSynchronizationDependencies
    {
        public bool IsElevated { get; init; } = true;
        public SynchronizationFailure Failure { get; init; }
        public bool HoldLock { get; init; }

        public bool StorageWasRead { get; private set; }
        public bool SemaphoreReleased { get; private set; }
        public bool SemaphoreDisposed { get; private set; }

        public StartupSynchronizationRequest SetupRequest() => Request(setupRequested: true);

        public StartupSynchronizationRequest RunRequest() => Request(setupRequested: false);

        private StartupSynchronizationRequest Request(bool setupRequested) => new(
            "storage",
            setupRequested,
            TimeSpan.Zero,
            new RecordingStorage(this),
            new RecordingMetadata(this),
            new RecordingSemaphores(this),
            new RecordingElevation(this),
            new RecordingAdministratorIdentity());

        private sealed class RecordingStorage(RecordingSynchronizationDependencies owner) : IProtectedStorageAdapter
        {
            public ProtectedStorageIdentity? EnsureProtectedStorageIdentity()
            {
                owner.StorageWasRead = true;
                return new ProtectedStorageIdentity("S-1-5-18");
            }

            public ProtectedStorageIdentity ValidateProtectedStorage()
            {
                owner.StorageWasRead = true;
                return new ProtectedStorageIdentity("S-1-5-18");
            }
        }

        private sealed class RecordingMetadata(RecordingSynchronizationDependencies owner) : ISynchronizationMetadataAdapter
        {
            public SynchronizationMetadata ResolveOrCreateForValidatedStorage(ProtectedStorageIdentity identity)
            {
                if (owner.Failure == SynchronizationFailure.Metadata)
                    throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
                return new SynchronizationMetadata(
                    1,
                    identity.AdministratorSid,
                    DeploymentIdentity.FromBytes(Enumerable.Repeat((byte)1, DeploymentIdentity.ByteLength).ToArray()));
            }
        }

        private sealed class RecordingSemaphores(RecordingSynchronizationDependencies owner) : INamedSemaphoreAdapter
        {
            public ISynchronizationLock OpenTrusted(SynchronizationMetadata metadata)
            {
                if (owner.Failure == SynchronizationFailure.Semaphore)
                    throw new UntrustedNamedSemaphoreException("A synchronization object could not be validated.");
                return new RecordingLock(owner, owner.HoldLock);
            }
        }

        private sealed class RecordingElevation(RecordingSynchronizationDependencies owner) : IAdministratorElevationAdapter
        {
            public bool IsElevated => owner.IsElevated;
        }

        private sealed class RecordingAdministratorIdentity : IConfigurationAdministratorIdentity
        {
            public string? CurrentAdministratorSid => "S-1-5-18";
        }

        private sealed class RecordingLock(RecordingSynchronizationDependencies owner, bool holdLock) : ISynchronizationLock
        {
            private bool acquired;

            public bool WaitOne(TimeSpan timeout)
            {
                if (holdLock) return false;
                acquired = true;
                return true;
            }

            public void Release()
            {
                if (acquired) owner.SemaphoreReleased = true;
            }

            public void Dispose() => owner.SemaphoreDisposed = true;
        }
    }
}
