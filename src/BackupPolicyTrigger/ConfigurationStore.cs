using System.Runtime.Versioning;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace BackupPolicyTrigger;

public sealed record ConfiguredTarget(string PolicyId, string PolicyName, string ResourceId, string ResourceName)
{
    /// <summary>
    /// True when both execution identifiers are present. A target with an empty
    /// policy or resource ID cannot be sent to the transport and is treated as
    /// not configured.
    /// </summary>
    public bool HasExecutionIds => PolicyId is { Length: > 0 } && ResourceId is { Length: > 0 };
}

public sealed record TriggerConfiguration(
    string DataCenterUrl,
    string ClientId,
    string ClientSecret,
    ConfiguredTarget? Target = null);


public interface ISecretProtector
{
    byte[] Protect(byte[] plaintext);
    byte[] Unprotect(byte[] ciphertext);
}

/// <summary>
/// Thrown when saved configuration exists but cannot be read as valid configuration.
/// </summary>
public sealed class ConfigurationUnreadableException(string message, Exception inner)
    : Exception(message, inner);

public sealed class ConfigurationStore(string directory, ISecretProtector protector)
{
    private const string FileName = "configuration.dat";
    private readonly string path = Path.Combine(directory, FileName);

    /// <summary>
    /// Persisted shape. Legacy installations stored the selected policy/resource as
    /// four positional fields; new saves store only the typed <see cref="ConfiguredTarget"/>.
    /// </summary>
    private sealed record StoredConfiguration(
        string DataCenterUrl,
        string ClientId,
        string ClientSecret,
        ConfiguredTarget? Target = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PolicyId = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? PolicyName = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ResourceId = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ResourceName = null);

    /// <summary>
    /// Creates protected storage on first setup. Existing storage is validated, not
    /// rebound, so another administrator cannot take over saved credentials.
    /// </summary>
    public void EnsureProtectedStorage() => EnsureProtectedStorageIdentity();

    internal ProtectedStorageIdentity? EnsureProtectedStorageIdentity()
    {
        if (!OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(directory);
            return null;
        }

        var administrator = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("Unable to determine the current Windows identity.");
        var security = new DirectorySecurity();
        Apply(
            security,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            administrator,
            InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit);
        CreateProtectedDirectory(directory, security);
        var identity = ValidateProtectedStorage(directory);
        if (identity.AdministratorSid != administrator.Value)
            throw new SynchronizationMetadataException("Protected storage belongs to a different Configuration administrator.");
        return identity;
    }

    public void Save(TriggerConfiguration configuration)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(configuration.DataCenterUrl);
        ArgumentException.ThrowIfNullOrWhiteSpace(configuration.ClientId);
        ArgumentException.ThrowIfNullOrWhiteSpace(configuration.ClientSecret);

        var storageIdentity = EnsureProtectedStorageIdentity();

        var plaintext = JsonSerializer.SerializeToUtf8Bytes(new StoredConfiguration(
            configuration.DataCenterUrl,
            configuration.ClientId,
            configuration.ClientSecret,
            configuration.Target));
        byte[] ciphertext;
        try
        {
            ciphertext = protector.Protect(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }

        // Write beside the target and swap, so an interrupted save never destroys
        // the only copy of the API client credentials.
        var staging = path + ".new";
        try
        {
            File.WriteAllBytes(staging, ciphertext);
            if (OperatingSystem.IsWindows()) Restrict(new FileInfo(staging), new SecurityIdentifier(storageIdentity!.AdministratorSid));

            if (File.Exists(path)) File.Replace(staging, path, null);
            else File.Move(staging, path);
        }
        catch
        {
            if (File.Exists(staging)) File.Delete(staging);
            throw;
        }

        if (OperatingSystem.IsWindows()) Restrict(new FileInfo(path), new SecurityIdentifier(storageIdentity!.AdministratorSid));
    }

    public TriggerConfiguration? Load()
    {
        byte[] stored;
        try
        {
            stored = File.ReadAllBytes(path);
        }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }

        byte[] plaintext;
        try
        {
            plaintext = protector.Unprotect(stored);
        }
        catch (CryptographicException exception)
        {
            throw new ConfigurationUnreadableException("Saved configuration cannot be decrypted on this machine.", exception);
        }

        try
        {
            var deserialized = JsonSerializer.Deserialize<StoredConfiguration>(plaintext)
                ?? throw new ConfigurationUnreadableException(
                    "Saved configuration is empty.", new InvalidDataException());

            var target = deserialized.Target ?? MigrateLegacyTarget(deserialized);
            return new TriggerConfiguration(
                deserialized.DataCenterUrl,
                deserialized.ClientId,
                deserialized.ClientSecret,
                target);
        }
        catch (JsonException exception)
        {
            throw new ConfigurationUnreadableException("Saved configuration is not valid.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static ConfiguredTarget? MigrateLegacyTarget(StoredConfiguration stored)
    {
        if (stored.PolicyId is not { Length: > 0 } policyId
            || stored.PolicyName is not { Length: > 0 } policyName
            || stored.ResourceId is not { Length: > 0 } resourceId
            || stored.ResourceName is not { Length: > 0 } resourceName)
        {
            return null;
        }

        return new ConfiguredTarget(policyId, policyName, resourceId, resourceName);
    }

    /// <summary>
    /// True when a configuration file exists on disk, regardless of whether it can
    /// currently be decrypted or deserialized. Replacement of unreadable state still
    /// requires explicit confirmation.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void CreateProtectedDirectory(string directory, DirectorySecurity security)
    {
        var descriptor = security.GetSecurityDescriptorBinaryForm();
        var descriptorPointer = Marshal.AllocHGlobal(descriptor.Length);
        var attributesPointer = Marshal.AllocHGlobal(Marshal.SizeOf<SecurityAttributes>());
        try
        {
            Marshal.Copy(descriptor, 0, descriptorPointer, descriptor.Length);
            Marshal.StructureToPtr(new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = descriptorPointer,
            }, attributesPointer, fDeleteOld: false);

            if (CreateDirectory(directory, attributesPointer)) return;
            if (Marshal.GetLastWin32Error() != 183)
                throw new IOException("Protected storage could not be created.");
        }
        finally
        {
            Marshal.FreeHGlobal(attributesPointer);
            Marshal.FreeHGlobal(descriptorPointer);
        }
    }

    public bool Exists() => File.Exists(path);

    [SupportedOSPlatform("windows")]
    internal static ProtectedStorageIdentity ValidateProtectedStorage(string directory)
    {
        using var handle = OpenDirectoryWithoutFollowingReparsePoint(directory);
        ValidateDirectoryHandle(handle);
        var security = GetDirectorySecurity(handle);
        var administrator = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (administrator is null
            || !security.AreAccessRulesProtected
            || !HasExactRules(
                security,
                administrator,
                InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit))
        {
            throw new SynchronizationMetadataException("Protected storage could not be validated.");
        }

        return new ProtectedStorageIdentity(administrator.Value);
    }

    [SupportedOSPlatform("windows")]
    private static SafeFileHandle OpenDirectoryWithoutFollowingReparsePoint(string directory)
    {
        var handle = CreateFile(
            directory,
            GenericRead | ReadControl,
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            BackupSemantics | OpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw new SynchronizationMetadataException("Protected storage could not be validated.");
        }

        return handle;
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateDirectoryHandle(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var information)
            || (information.FileAttributes & ReparsePointAttribute) != 0)
        {
            throw new SynchronizationMetadataException("Protected storage could not be validated.");
        }
    }

    [SupportedOSPlatform("windows")]
    private static DirectorySecurity GetDirectorySecurity(SafeFileHandle handle)
    {
        var status = GetSecurityInfo(
            handle,
            FileObjectSecurity,
            OwnerSecurityInformation | DaclSecurityInformation,
            out _,
            out _,
            out _,
            out _,
            out var descriptor);
        if (status != 0 || descriptor == IntPtr.Zero)
            throw new SynchronizationMetadataException("Protected storage could not be validated.");

        try
        {
            var bytes = new byte[GetSecurityDescriptorLength(descriptor)];
            Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            var security = new DirectorySecurity();
            security.SetSecurityDescriptorBinaryForm(bytes);
            return security;
        }
        finally
        {
            LocalFree(descriptor);
        }
    }
    public void Reset()
    {
        if (File.Exists(path)) File.Delete(path);
    }

[SupportedOSPlatform("windows")]
    internal static void Restrict(FileSystemInfo target, SecurityIdentifier administrator)
    {
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var inheritance = target is DirectoryInfo
            ? InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit
            : InheritanceFlags.None;

        switch (target)
        {
            case DirectoryInfo dir:
            {
                var security = new DirectorySecurity();
                Apply(security, system, administrator, inheritance);
                dir.SetAccessControl(security);
                break;
            }
            case FileInfo file:
            {
                var security = new FileSecurity();
                Apply(security, system, administrator, inheritance);
                file.SetAccessControl(security);
                break;
            }
        }
    }

[SupportedOSPlatform("windows")]
    internal static void Apply(
        FileSystemSecurity security,
        SecurityIdentifier system,
        SecurityIdentifier administrator,
        InheritanceFlags inheritance)
    {
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(administrator);
        foreach (FileSystemAccessRule existing in security.GetAccessRules(true, false, typeof(SecurityIdentifier)))
            security.RemoveAccessRuleAll(existing);

        security.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(administrator, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
    }

[SupportedOSPlatform("windows")]
    internal static bool HasExactRules(
        FileSystemSecurity security,
        SecurityIdentifier administrator,
        InheritanceFlags inheritance)
    {
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToArray();
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

        return rules.Length == 2
            && rules.All(rule =>
                rule.AccessControlType == AccessControlType.Allow
                && rule.FileSystemRights == FileSystemRights.FullControl
                && rule.PropagationFlags == PropagationFlags.None
                && rule.InheritanceFlags == inheritance
                && !rule.IsInherited
                && rule.IdentityReference is SecurityIdentifier sid
                && (sid == system || sid == administrator))
            && rules.Select(rule => (SecurityIdentifier)rule.IdentityReference).Distinct().Count() == 2;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        public bool InheritHandle;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectory(string path, IntPtr securityAttributes);

    private const uint GenericRead = 0x80000000;
    private const uint ReadControl = 0x00020000;
    private const uint FileShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const uint BackupSemantics = 0x02000000;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint ReparsePointAttribute = 0x00000400;
    private const uint FileObjectSecurity = 1;
    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint DaclSecurityInformation = 0x00000004;

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public uint CreationTimeLow;
        public uint CreationTimeHigh;
        public uint LastAccessTimeLow;
        public uint LastAccessTimeHigh;
        public uint LastWriteTimeLow;
        public uint LastWriteTimeHigh;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string path,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle handle,
        out ByHandleFileInformation information);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityInfo(
        SafeFileHandle handle,
        uint objectType,
        uint requestedInformation,
        out IntPtr owner,
        out IntPtr group,
        out IntPtr dacl,
        out IntPtr sacl,
        out IntPtr securityDescriptor);

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(IntPtr securityDescriptor);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

}

[SupportedOSPlatform("windows")]
public sealed class WindowsDpapiProtector : ISecretProtector
{
    public byte[] Protect(byte[] plaintext) => ProtectedData.Protect(plaintext, null, DataProtectionScope.LocalMachine);
    public byte[] Unprotect(byte[] ciphertext) => ProtectedData.Unprotect(ciphertext, null, DataProtectionScope.LocalMachine);
}
