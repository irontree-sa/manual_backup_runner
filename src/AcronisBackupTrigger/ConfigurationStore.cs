using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AcronisBackupTrigger;

public sealed record ConfiguredTarget(string PolicyId, string PolicyName, string ResourceId, string ResourceName);

public sealed record TriggerConfiguration(
    string DataCenterUrl,
    string ClientId,
    string ClientSecret,
    ConfiguredTarget? Target = null);

/// <summary>
/// Persisted shape. Legacy installations stored the selected policy/resource as four
/// positional fields; new saves store only the typed <see cref="ConfiguredTarget"/>.
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
    private readonly string path = Path.Combine(directory, FileName);

    public void Save(TriggerConfiguration configuration)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(configuration.DataCenterUrl);
        ArgumentException.ThrowIfNullOrWhiteSpace(configuration.ClientId);
        ArgumentException.ThrowIfNullOrWhiteSpace(configuration.ClientSecret);

        Directory.CreateDirectory(directory);
        if (OperatingSystem.IsWindows()) Restrict(new DirectoryInfo(directory));

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
            if (OperatingSystem.IsWindows()) Restrict(new FileInfo(staging));

            if (File.Exists(path)) File.Replace(staging, path, null);
            else File.Move(staging, path);
        }
        catch
        {
            if (File.Exists(staging)) File.Delete(staging);
            throw;
        }

        if (OperatingSystem.IsWindows()) Restrict(new FileInfo(path));
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
            var stored = JsonSerializer.Deserialize<StoredConfiguration>(plaintext)
                ?? throw new ConfigurationUnreadableException(
                    "Saved configuration is empty.", new InvalidDataException());

            var target = stored.Target ?? MigrateLegacyTarget(stored);
            return new TriggerConfiguration(
                stored.DataCenterUrl,
                stored.ClientId,
                stored.ClientSecret,
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
            || stored.ResourceId is not { Length: > 0 } resourceId)
        {
            return null;
        }

        return new ConfiguredTarget(
            policyId,
            stored.PolicyName ?? policyId,
            resourceId,
            stored.ResourceName ?? resourceId);
    }

    /// <summary>
    /// True when a configuration file exists on disk, regardless of whether it can
    /// currently be decrypted or deserialized. Replacement of unreadable state still
    /// requires explicit confirmation.
    /// </summary>
    public bool Exists() => File.Exists(path);

    public void Reset()
    {
        if (File.Exists(path)) File.Delete(path);
    }

    [SupportedOSPlatform("windows")]
    private static void Restrict(FileSystemInfo target)
    {
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrator = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("Unable to determine the current Windows identity.");

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
    private static void Apply(
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
}

[SupportedOSPlatform("windows")]
public sealed class WindowsDpapiProtector : ISecretProtector
{
    public byte[] Protect(byte[] plaintext) => ProtectedData.Protect(plaintext, null, DataProtectionScope.LocalMachine);
    public byte[] Unprotect(byte[] ciphertext) => ProtectedData.Unprotect(ciphertext, null, DataProtectionScope.LocalMachine);
}
