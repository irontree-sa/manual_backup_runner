using System.Security.AccessControl;
using System.Security.Cryptography;
using BackupPolicyTrigger;

namespace BackupPolicyTrigger.WindowsVerification;

/// <summary>
/// Owns one isolated verification fixture under the temporary directory. The
/// fixture root is a randomized normal directory; each check requests its own
/// protected child so a corrupted ACL on one child can never affect another.
/// The opaque token (never the path) is what crosses the child-process boundary.
/// </summary>
internal sealed class HarnessFixture : IDisposable
{
    public const string ContentionDirectoryName = "contention";
    private const string BaseDirectoryName = "BackupPolicyTrigger.WindowsVerification";

    private readonly string root;
    private readonly List<string> children = new();
    private bool disposed;

    public string Token { get; }
    public string RootPath => root;

    private HarnessFixture(string token, string root)
    {
        Token = token;
        this.root = root;
    }

    public static HarnessFixture Create()
    {
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var root = ResolveRoot(token);
        Directory.CreateDirectory(root);
        return new HarnessFixture(token, root);
    }

    /// <summary>Reconstructs the fixture root from an opaque token. The token is
    /// random and never encodes the path; the path is derived deterministically.</summary>
    public static string ResolveRoot(string token) =>
        Path.Combine(Path.GetTempPath(), BaseDirectoryName, token);

    /// <summary>Creates a protected child directory for one check. Each destructive
    /// check gets its own child so no corrupted ACL can affect another check.</summary>
    public string CreateProtectedChild() => CreateProtectedChild(Guid.NewGuid().ToString("N"));

    public string CreateProtectedChild(string name)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var child = Path.Combine(root, name);
        var store = new ConfigurationStore(child, new WindowsDpapiProtector());
        _ = store.EnsureProtectedStorageIdentity();
        children.Add(child);
        return child;
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        foreach (var child in children)
            DeleteKnownChild(child);
        DeleteKnownChild(root);
    }

    /// <summary>Unlinks a reparse point without traversing its target, and
    /// recursively deletes only a verified normal directory.</summary>
    private static void DeleteKnownChild(string path)
    {
        if (!Directory.Exists(path)) return;
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            Directory.Delete(path, recursive: false);
            return;
        }
        Directory.Delete(path, recursive: true);
    }
}
