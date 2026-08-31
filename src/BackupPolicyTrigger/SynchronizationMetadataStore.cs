using System.Collections.Concurrent;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Text.Json;

namespace BackupPolicyTrigger;

internal sealed record ProtectedStorageIdentity(string AdministratorSid);

internal sealed record SynchronizationMetadata(int Version, string AdministratorSid, DeploymentIdentity Identifier);

internal sealed class SynchronizationMetadataException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// Seam for the file-handle operations that publication and cleanup validation
/// depend on. Production uses the Windows P/Invoke implementation inside
/// <see cref="SynchronizationMetadataStore"/>; tests inject a recording fake so
/// validation ordering and disposition can be observed without constructing
/// Windows-only ACL objects.
/// </summary>
internal interface IMetadataFileApi
{
    /// <summary>Reopens the known temporary path without following reparse points and
    /// validates regular-file state, owner, protected DACL, and exact rules.</summary>
    void ValidateForPublication(string path, string administratorSid);

    /// <summary>Validates the same state/owner/DACL before the temporary is disposed.</summary>
    void ValidateForCleanup(string path, string administratorSid);

    /// <summary>Requests delete disposition for the given path only.</summary>
    void RequestDisposition(string path);
}

/// <summary>
/// Persists the private deployment identity only after protected storage has been
/// validated. The published file is never a partially written destination.
/// </summary>
internal sealed class SynchronizationMetadataStore
{
    private const int FormatVersion = 1;
    private const string FileName = "synchronization.json";
    private static readonly ConcurrentDictionary<string, object> NonWindowsPublicationGates = new(StringComparer.Ordinal);
    private readonly string directory;
    private readonly IMetadataFileApi? api;
    private readonly string path;

    public SynchronizationMetadataStore(string directory, IMetadataFileApi? api = null)
    {
        this.directory = directory;
        this.api = api;
        this.path = Path.Combine(directory, FileName);
    }

    private sealed record StoredMetadata(int Version, string AdministratorSid, string Identifier);

    public SynchronizationMetadata ResolveExisting(ProtectedStorageIdentity identity) =>
        Parse(ReadPublishedFile(identity), identity);

    public SynchronizationMetadata ResolveOrCreateForValidatedStorage(ProtectedStorageIdentity identity)
    {
        if (!OperatingSystem.IsWindows())
        {
            lock (NonWindowsPublicationGates.GetOrAdd(path, static _ => new object()))
            {
                return ResolveOrCreateCore(identity);
            }
        }

        return ResolveOrCreateCore(identity);
    }

    private SynchronizationMetadata ResolveOrCreateCore(ProtectedStorageIdentity identity)
    {
        try
        {
            return ResolveExisting(identity);
        }
        catch (FileNotFoundException)
        {
            return CreateOrReadPublished(identity);
        }
    }

    private SynchronizationMetadata CreateOrReadPublished(ProtectedStorageIdentity identity)
    {
        var temporary = Path.Combine(directory, $".{FileName}.{Guid.NewGuid():N}.tmp");
        try
        {
            var metadata = new SynchronizationMetadata(FormatVersion, identity.AdministratorSid, DeploymentIdentity.CreateRandom());
            var serialized = JsonSerializer.SerializeToUtf8Bytes(new StoredMetadata(
                metadata.Version,
                metadata.AdministratorSid,
                ToBase64Url(metadata.Identifier.Bytes)));

            try
            {
                using (var stream = CreateProtectedTemporary(temporary, identity.AdministratorSid))
                {
                    stream.Write(serialized);
                    stream.Flush(flushToDisk: true);
                }
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(serialized);
            }

            ValidateTemporaryForPublication(temporary, identity.AdministratorSid);

            try
            {
                File.Move(temporary, path, overwrite: false);
                return ResolveExisting(identity);
            }
            catch (IOException) when (File.Exists(path))
            {
                return ResolveExisting(identity);
            }
        }
        catch (SynchronizationMetadataException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or JsonException
            or ArgumentException)
        {
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.", exception);
        }
        finally
        {
            DeleteTemporary(temporary, identity.AdministratorSid);
        }
    }

    private byte[] ReadPublishedFile(ProtectedStorageIdentity identity)
    {
        if (!OperatingSystem.IsWindows())
        {
            var info = new FileInfo(path);
            if (!info.Exists) throw new FileNotFoundException("Synchronization metadata does not exist.", path);
            if (info.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
            return File.ReadAllBytes(path);
        }

        using var handle = OpenExistingFileWithoutFollowingReparsePoint(path);
        ValidateRegularFileHandle(handle);
        var security = GetHandleSecurity(handle);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner?.Value != identity.AdministratorSid
            || !security.AreAccessRulesProtected
            || !ConfigurationStore.HasExactRules(security, owner!, InheritanceFlags.None))
        {
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
        }

        using var stream = new FileStream(handle, FileAccess.Read);
        using var output = new MemoryStream();
        stream.CopyTo(output);
        return output.ToArray();
    }

    private static SynchronizationMetadata Parse(byte[] bytes, ProtectedStorageIdentity identity)
    {
        try
        {
            using var document = JsonDocument.Parse(bytes);
            if (!HasExactSchema(document.RootElement))
            {
                throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
            }

            var stored = JsonSerializer.Deserialize<StoredMetadata>(bytes)
                ?? throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
            if (stored.Version != FormatVersion
                || !IsValidAdministratorSid(stored.AdministratorSid)
                || !AdministratorSidMatches(stored.AdministratorSid, identity.AdministratorSid))
            {
                throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
            }

            return new SynchronizationMetadata(
                stored.Version,
                stored.AdministratorSid,
                DeploymentIdentity.FromBytes(FromBase64Url(stored.Identifier)));
        }
        catch (Exception exception) when (exception is JsonException
            or FormatException
            or ArgumentException)
        {
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.", exception);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
        }
    }

    internal static bool HasExactSchema(JsonElement root) =>
        root.ValueKind == JsonValueKind.Object
        && root.EnumerateObject().Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .SequenceEqual(["AdministratorSid", "Identifier", "Version"]);

    internal static bool IsValidAdministratorSid(string value)
    {
        var parts = value.Split('-');
        if (parts.Length < 4
            || !string.Equals(parts[0], "S", StringComparison.OrdinalIgnoreCase)
            || !uint.TryParse(parts[1], out _)
            || !TryParseSidAuthority(parts[2]))
        {
            return false;
        }

        return parts.Skip(3).All(part => uint.TryParse(part, out _));
    }

    private static bool AdministratorSidMatches(string stored, string expected)
    {
        if (OperatingSystem.IsWindows())
        {
            var administrator = new SecurityIdentifier(stored);
            return string.Equals(administrator.Value, expected, StringComparison.Ordinal);
        }

        return string.Equals(stored, expected, StringComparison.Ordinal);
    }

    private static bool TryParseSidAuthority(string value) =>
        ulong.TryParse(value, out _)
        || (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            && ulong.TryParse(value[2..], System.Globalization.NumberStyles.AllowHexSpecifier, null, out _));
    private static string ToBase64Url(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static FileStream CreateProtectedTemporary(string path, string administratorSid)
    {
        var stream = OperatingSystem.IsWindows()
            ? new FileStream(OpenNewFileWithSecurityRights(path), FileAccess.ReadWrite)
            : new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.WriteThrough);
        try
        {
            if (!OperatingSystem.IsWindows()) return stream;

            var administrator = new SecurityIdentifier(administratorSid);

            ValidateRegularFileHandle(stream.SafeFileHandle);
            var security = new FileSecurity();
            ConfigurationStore.Apply(
                security,
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                administrator,
                InheritanceFlags.None);
            ApplySecurityByHandle(stream.SafeFileHandle, security);

            var applied = GetHandleSecurity(stream.SafeFileHandle);
            var owner = applied.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (owner != administrator
                || !applied.AreAccessRulesProtected
                || !ConfigurationStore.HasExactRules(applied, administrator, InheritanceFlags.None))
            {
                throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
            }

            ValidateRegularFileHandle(stream.SafeFileHandle);
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    private void ValidateTemporaryForPublication(string temporary, string administratorSid)
    {
        if (api is not null)
        {
            api.ValidateForPublication(temporary, administratorSid);
            return;
        }

        if (!OperatingSystem.IsWindows())
        {
            var info = new FileInfo(temporary);
            if (!info.Exists || info.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
            return;
        }

        using var handle = OpenExistingFileWithoutFollowingReparsePoint(temporary, GenericRead | ReadControl);
        ValidateRegularFileHandle(handle);
        var security = GetHandleSecurity(handle);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner?.Value != administratorSid
            || !security.AreAccessRulesProtected
            || !ConfigurationStore.HasExactRules(security, owner!, InheritanceFlags.None))
        {
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
        }
    }

    private static void ValidateRegularFileHandle(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var information)
            || (information.FileAttributes & ReparsePointAttribute) != 0)
        {
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
        }
    }

    private static SafeFileHandle OpenNewFileWithSecurityRights(string path)
    {
        var handle = CreateFile(
            path,
            GenericRead | GenericWrite | ReadControl | WriteDac | WriteOwner,
            0,
            IntPtr.Zero,
            CreateNew,
            0,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
        }

        return handle;
    }

    private static void ApplySecurityByHandle(SafeFileHandle handle, FileSecurity security)
    {
        var descriptor = security.GetSecurityDescriptorBinaryForm();
        var pinned = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
        try
        {
            var pointer = pinned.AddrOfPinnedObject();
            if (!GetSecurityDescriptorOwner(pointer, out var owner, out _)
                || !GetSecurityDescriptorDacl(pointer, out var present, out var dacl, out _)
                || !present
                || SetSecurityInfo(handle, FileObjectSecurity, OwnerSecurityInformation | DaclSecurityInformation, owner, IntPtr.Zero, dacl, IntPtr.Zero) != 0)
            {
                throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
            }
        }
        finally
        {
            pinned.Free();
        }
    }

    private void DeleteTemporary(string path, string administratorSid)
    {
        if (!File.Exists(path)) return;

        if (api is not null)
        {
            api.ValidateForCleanup(path, administratorSid);
            api.RequestDisposition(path);
            return;
        }

        if (!OperatingSystem.IsWindows())
        {
            File.Delete(path);
            return;
        }

        using var handle = OpenExistingFileWithoutFollowingReparsePoint(path, GenericRead | Delete);
        ValidateRegularFileHandle(handle);
        var security = GetHandleSecurity(handle);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null
            || !security.AreAccessRulesProtected
            || !ConfigurationStore.HasExactRules(security, owner, InheritanceFlags.None))
        {
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
        }

        var disposition = new FileDispositionInformation { DeleteFile = true };
        if (!SetFileInformationByHandle(handle, FileDispositionInfo, ref disposition, (uint)Marshal.SizeOf<FileDispositionInformation>()))
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
    }


    private static SafeFileHandle OpenExistingFileWithoutFollowingReparsePoint(string path, uint desiredAccess = GenericRead)
    {
        var handle = CreateFile(
            path,
            desiredAccess,
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            OpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            if (IsMissingPathError(error))
                throw new FileNotFoundException("Synchronization metadata does not exist.", path);
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");
        }


        return handle;
    }
    internal static bool IsMissingPathError(int error) => error is 2 or 3;


    private static FileSecurity GetHandleSecurity(SafeFileHandle handle)
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
            throw new SynchronizationMetadataException("Synchronization metadata could not be validated.");

        try
        {
            var bytes = new byte[GetSecurityDescriptorLength(descriptor)];
            Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            var security = new FileSecurity();
            security.SetSecurityDescriptorBinaryForm(bytes);
            return security;
        }
        finally
        {
            LocalFree(descriptor);
        }
    }

    private static byte[] FromBase64Url(string value)
    {
        if (value.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '-' or '_')))
            throw new FormatException("Metadata identifier is not Base64Url.");

        var padded = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded.PadRight((padded.Length + 3) / 4 * 4, '='));
    }
    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint DaclSecurityInformation = 0x00000004;
    private const uint ReparsePointAttribute = 0x00000400;
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint FileObjectSecurity = 1;
    private const uint GenericWrite = 0x40000000;
    private const uint ReadControl = 0x00020000;
    private const uint WriteDac = 0x00040000;
    private const uint Delete = 0x00010000;
    private const int FileDispositionInfo = 4;

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInformation
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool DeleteFile;
    }
    private const uint WriteOwner = 0x00080000;
    private const uint CreateNew = 1;

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

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle handle,
        out ByHandleFileInformation information);

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
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle handle,
        int fileInformationClass,
        ref FileDispositionInformation fileInformation,
        uint bufferSize);

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

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorOwner(
        IntPtr securityDescriptor,
        out IntPtr owner,
        [MarshalAs(UnmanagedType.Bool)] out bool ownerDefaulted);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorDacl(
        IntPtr securityDescriptor,
        [MarshalAs(UnmanagedType.Bool)] out bool daclPresent,
        out IntPtr dacl,
        [MarshalAs(UnmanagedType.Bool)] out bool daclDefaulted);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint SetSecurityInfo(
        SafeFileHandle handle,
        uint objectType,
        uint requestedInformation,
        IntPtr owner,
        IntPtr group,
        IntPtr dacl,
        IntPtr sacl);
}
