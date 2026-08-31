using System.Security.AccessControl;
using BackupPolicyTrigger;

namespace BackupPolicyTrigger.Tests;

public sealed class NamedSemaphoreFactoryTests
{
    private const string AdministratorSid = "S-1-5-32-544";

    private static SynchronizationMetadata Metadata =>
        new(1, AdministratorSid, DeploymentIdentity.FromBytes(Enumerable.Repeat((byte)1, DeploymentIdentity.ByteLength).ToArray()));

    private static NamedSemaphoreDescriptor TrustedDescriptor() => new(
        NamedObjectType.Semaphore,
        IsDaclProtected: true,
        Aces:
        [
            new("S-1-5-18", AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None),
            new(AdministratorSid, AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None),
        ]);

    [Fact]
    public void DeriveName_uses_distinct_domains_and_deployment_identities()
    {
        var first = DeploymentIdentity.FromBytes(Enumerable.Repeat((byte)1, DeploymentIdentity.ByteLength).ToArray());
        var second = DeploymentIdentity.FromBytes(Enumerable.Repeat((byte)2, DeploymentIdentity.ByteLength).ToArray());

        var machine = NamedSemaphoreFactory.DeriveName(first, SynchronizationLockPurpose.MachineRun);
        var audit = NamedSemaphoreFactory.DeriveName(first, SynchronizationLockPurpose.AuditLog);
        var otherMachine = NamedSemaphoreFactory.DeriveName(second, SynchronizationLockPurpose.MachineRun);

        Assert.StartsWith("Global\\", machine, StringComparison.Ordinal);
        Assert.NotEqual(machine, audit);
        Assert.NotEqual(machine, otherMachine);
        Assert.DoesNotContain("BackupPolicyTrigger", machine, StringComparison.Ordinal);
    }

    public static IEnumerable<object[]> UntrustedDescriptors()
    {
        yield return [ExtraAce()];
        yield return [InheritedAce()];
        yield return [DenyAce()];
        yield return [WrongAdministratorSid()];
        yield return [AlteredRights()];
        yield return [UnprotectedDacl()];
        yield return [ObjectTypeCollision()];
    }

    [Theory]
    [MemberData(nameof(UntrustedDescriptors))]
    public void OpenTrusted_rejects_untrusted_existing_descriptor(NamedSemaphoreDescriptor descriptor)
    {
        var api = new FakeNamedSemaphoreApi(createdNewFlag: false, descriptor);

        Assert.Throws<UntrustedNamedSemaphoreException>(() =>
            new NamedSemaphoreFactory(api).OpenTrusted(Metadata, SynchronizationLockPurpose.MachineRun));
    }

    [Fact]
    public void OpenTrusted_rejects_unreadable_existing_descriptor()
    {
        var api = new FakeNamedSemaphoreApi(createdNewFlag: false, TrustedDescriptor()) { ThrowOnGetSecurity = true };

        Assert.Throws<UntrustedNamedSemaphoreException>(() =>
            new NamedSemaphoreFactory(api).OpenTrusted(Metadata, SynchronizationLockPurpose.MachineRun));
    }

    [Fact]
    public void OpenTrusted_accepts_matching_protected_descriptor()
    {
        var api = new FakeNamedSemaphoreApi(createdNewFlag: false, TrustedDescriptor());

        using var semaphore = new NamedSemaphoreFactory(api).OpenTrusted(Metadata, SynchronizationLockPurpose.MachineRun);

        Assert.True(api.ObservedExpectedDacl);
    }

    [Fact]
    public void OpenTrusted_accepts_newly_created_object()
    {
        var api = new FakeNamedSemaphoreApi(createdNewFlag: true, TrustedDescriptor());

        using var semaphore = new NamedSemaphoreFactory(api).OpenTrusted(Metadata, SynchronizationLockPurpose.MachineRun);

        Assert.True(api.ObservedExpectedDacl);
    }

    private static NamedSemaphoreDescriptor ExtraAce() => new(
        NamedObjectType.Semaphore,
        IsDaclProtected: true,
        Aces:
        [
            new("S-1-5-18", AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None),
            new(AdministratorSid, AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None),
            new("S-1-5-32-545", AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None),
        ]);

    private static NamedSemaphoreDescriptor InheritedAce() => new(
        NamedObjectType.Semaphore,
        IsDaclProtected: true,
        Aces:
        [
            new("S-1-5-18", AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None),
            new(AdministratorSid, AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.ContainerInherit, PropagationFlags.None),
        ]);

    private static NamedSemaphoreDescriptor DenyAce() => new(
        NamedObjectType.Semaphore,
        IsDaclProtected: true,
        Aces:
        [
            new("S-1-5-18", AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None),
            new(AdministratorSid, AccessControlType.Deny, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None),
        ]);

    private static NamedSemaphoreDescriptor WrongAdministratorSid() => new(
        NamedObjectType.Semaphore,
        IsDaclProtected: true,
        Aces:
        [
            new("S-1-5-18", AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None),
            new("S-1-5-32-545", AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None),
        ]);

    private static NamedSemaphoreDescriptor AlteredRights() => new(
        NamedObjectType.Semaphore,
        IsDaclProtected: true,
        Aces:
        [
            new("S-1-5-18", AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None),
            new(AdministratorSid, AccessControlType.Allow, SemaphoreRights.Modify, InheritanceFlags.None, PropagationFlags.None),
        ]);

    private static NamedSemaphoreDescriptor UnprotectedDacl() => new(
        NamedObjectType.Semaphore,
        IsDaclProtected: false,
        Aces:
        [
            new("S-1-5-18", AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None),
            new(AdministratorSid, AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None),
        ]);

    private static NamedSemaphoreDescriptor ObjectTypeCollision() => new(
        NamedObjectType.Mutex,
        IsDaclProtected: true,
        Aces:
        [
            new("S-1-5-18", AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None),
            new(AdministratorSid, AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None),
        ]);

    private sealed class FakeNamedSemaphoreApi(bool createdNewFlag, NamedSemaphoreDescriptor descriptor) : INamedSemaphoreApi
    {
        private NamedSemaphoreDescriptor? expected;
        public bool ThrowOnGetSecurity { get; set; }

        public bool ObservedExpectedDacl =>
            expected is { IsDaclProtected: true } e
            && e.Aces.Count == 2
            && e.Aces.All(ace => ace.Type == AccessControlType.Allow && ace.Rights == SemaphoreRights.FullControl);

        public Semaphore Create(string name, NamedSemaphoreDescriptor security, out bool createdNew)
        {
            expected = security;
            createdNew = createdNewFlag;
            return new Semaphore(1, 1);
        }

        public NamedSemaphoreDescriptor GetSecurity(Semaphore semaphore)
        {
            if (ThrowOnGetSecurity)
                throw new UnauthorizedAccessException("Access is denied.");
            return descriptor;
        }
    }
}
