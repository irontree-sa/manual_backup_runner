namespace AcronisBackupTrigger;

/// <summary>A root <c>policy.protection.total</c> protection policy.</summary>
public sealed record AcronisPolicy(string Id, string Name);

/// <summary>A protected Acronis resource assigned to a protection policy.</summary>
public sealed record AcronisResource(string Id, string Name);

public enum DiscoveryStatus
{
    Succeeded,
    AuthenticationFailed,
    AcronisRejected,
    InvalidDataCenterUrl,
    ConnectivityFailed,
    AcronisUnavailable,
    UnexpectedResponse,
}

public sealed record DiscoveryResult<T>(DiscoveryStatus Status, IReadOnlyList<T> Items)
{
    public static DiscoveryResult<T> Failed(DiscoveryStatus status) => new(status, []);
}
