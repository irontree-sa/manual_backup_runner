using System.Runtime.Versioning;
using BackupPolicyTrigger;

[assembly: SupportedOSPlatform("windows")]

namespace BackupPolicyTrigger.WindowsVerification;

public static class Program
{
    public static int Main(string[] args)
    {
        // Help is static and secret-free, so it is available on any platform
        // before the Windows guard. It never touches fixtures, storage, or
        // synchronization objects.
        if (args.Length == 1 && string.Equals(args[0], "--help", StringComparison.OrdinalIgnoreCase))
        {
            Console.Out.WriteLine(HarnessHelp.Text);
            return ExitCodes.Success;
        }

        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("The verification harness must run on Windows.");
            return ExitCodes.UnsupportedPlatform;
        }

        if (args.Length == 2 && string.Equals(args[0], "--child-publish", StringComparison.OrdinalIgnoreCase))
            return HarnessChecks.RunChildPublisher(args[1]);

        return HarnessChecks.RunParentSuite();
    }
}

internal static class HarnessHelp
{
    public const string Text =
        """
        Backup Policy Trigger Windows Verification

        Verifies protected-storage, metadata, semaphore, and orchestration
        security on a Windows host. Every check runs against an isolated
        fixture under the temporary directory; production storage is never
        touched and no transport is constructed.

        Usage:
          BackupPolicyTrigger.WindowsVerification.exe
              Run every check and report one PASS/FAIL line per check.

          BackupPolicyTrigger.WindowsVerification.exe --child-publish <token>
              Run one contention child against the shared fixture identified
              by the opaque token. Internal to the parent suite.

          BackupPolicyTrigger.WindowsVerification.exe --help
              Print this guide.

        Exit codes:
          0  Every check passed.
          1  One or more checks failed.
          2  This executable must run on Windows.
        """;
}
