using System.Runtime.Versioning;
using System.Security.Principal;

namespace BackupPolicyTrigger;

public interface IAdministratorGate
{
    bool IsElevated { get; }
}

[SupportedOSPlatform("windows")]
public sealed class WindowsAdministratorGate : IAdministratorGate, IAdministratorElevationAdapter
{
    public bool IsElevated
    {
        get
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}

public sealed class AllowAdministratorGate : IAdministratorGate
{
    public bool IsElevated => true;
}
