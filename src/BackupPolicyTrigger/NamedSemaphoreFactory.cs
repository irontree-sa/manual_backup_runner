using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace BackupPolicyTrigger;

internal enum SynchronizationLockPurpose { MachineRun, AuditLog }

internal sealed class UntrustedNamedSemaphoreException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// Platform-neutral model of a named-object security descriptor. The Windows
/// adapter converts this to and from <see cref="SemaphoreSecurity"/>; tests
/// compare descriptors directly so rejection assertions execute on any OS
/// without constructing Windows ACL objects.
internal sealed record NamedSemaphoreAce(
    string IdentitySid,
    AccessControlType Type,
    SemaphoreRights Rights,
    InheritanceFlags Inheritance,
    PropagationFlags Propagation,
    bool IsInherited);

internal sealed record NamedSemaphoreDescriptor(
    bool IsDaclProtected,
    IReadOnlyList<NamedSemaphoreAce> Aces);

internal interface INamedSemaphoreApi
{
    Semaphore Create(string name, NamedSemaphoreDescriptor descriptor, out bool createdNew);
    NamedSemaphoreDescriptor GetSecurity(Semaphore semaphore);
}

internal sealed class NamedSemaphoreFactory(INamedSemaphoreApi? api = null)
{
    private readonly INamedSemaphoreApi semaphoreApi = api ?? new WindowsNamedSemaphoreApi();
    private readonly bool useKernelObjects = api is not null || OperatingSystem.IsWindows();

    public Semaphore OpenTrusted(SynchronizationMetadata metadata, SynchronizationLockPurpose purpose)
    {
        if (!useKernelObjects) return new Semaphore(1, 1);

        var descriptor = CreateDescriptor(metadata.AdministratorSid);
        Semaphore? semaphore = null;
        try
        {
            semaphore = semaphoreApi.Create(DeriveName(metadata.Identifier, purpose), descriptor, out var createdNew);
            if (!createdNew && !Equivalent(descriptor, semaphoreApi.GetSecurity(semaphore)))
                throw new UntrustedNamedSemaphoreException("A synchronization object could not be validated.");
            return semaphore;
        }
        catch (UntrustedNamedSemaphoreException)
        {
            semaphore?.Dispose();
            throw;
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or WaitHandleCannotBeOpenedException
            or ArgumentException)
        {
            semaphore?.Dispose();
            throw new UntrustedNamedSemaphoreException("A synchronization object could not be validated.", exception);
        }
    }

    internal static string DeriveName(DeploymentIdentity identity, SynchronizationLockPurpose purpose)
    {
        var domain = purpose == SynchronizationLockPurpose.MachineRun
            ? "BackupPolicyTrigger/machine/v1"
            : "BackupPolicyTrigger/audit/v1";
        var digest = HMACSHA256.HashData(identity.Bytes, Encoding.UTF8.GetBytes(domain));
        return $"Global\\{Convert.ToBase64String(digest).TrimEnd('=').Replace('+', '-').Replace('/', '_')}";
    }

    private static NamedSemaphoreDescriptor CreateDescriptor(string administratorSid) =>
        new(
            IsDaclProtected: true,
            Aces:
            [
                new("S-1-5-18", AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None, IsInherited: false),
                new(administratorSid, AccessControlType.Allow, SemaphoreRights.FullControl, InheritanceFlags.None, PropagationFlags.None, IsInherited: false),
            ]);

    private static bool Equivalent(NamedSemaphoreDescriptor expected, NamedSemaphoreDescriptor actual) =>
        expected.IsDaclProtected == actual.IsDaclProtected
        && expected.Aces.Count == actual.Aces.Count
        && expected.Aces.Zip(actual.Aces).All(pair => pair.First == pair.Second);

    private sealed class WindowsNamedSemaphoreApi : INamedSemaphoreApi
    {
        public Semaphore Create(string name, NamedSemaphoreDescriptor descriptor, out bool createdNew)
        {
            var security = ToSemaphoreSecurity(descriptor);
            return SemaphoreAcl.Create(1, 1, name, out createdNew, security);
        }

        public NamedSemaphoreDescriptor GetSecurity(Semaphore semaphore) =>
            FromSemaphoreSecurity(semaphore.GetAccessControl());

        private static SemaphoreSecurity ToSemaphoreSecurity(NamedSemaphoreDescriptor descriptor)
        {
            var security = new SemaphoreSecurity();
            security.SetAccessRuleProtection(descriptor.IsDaclProtected, preserveInheritance: false);
            foreach (var ace in descriptor.Aces)
                security.AddAccessRule(new SemaphoreAccessRule(
                    new SecurityIdentifier(ace.IdentitySid), ace.Rights, ace.Type));
            return security;
        }
        private static NamedSemaphoreDescriptor FromSemaphoreSecurity(SemaphoreSecurity security)
        {
            var aces = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
                .Cast<SemaphoreAccessRule>()
                .Select(rule => new NamedSemaphoreAce(
                    rule.IdentityReference.Value,
                    rule.AccessControlType,
                    rule.SemaphoreRights,
                    rule.InheritanceFlags,
                    rule.PropagationFlags,
                    rule.IsInherited))
                .ToList();
            return new NamedSemaphoreDescriptor(
                security.AreAccessRulesProtected,
                aces);
        }
    }
}
