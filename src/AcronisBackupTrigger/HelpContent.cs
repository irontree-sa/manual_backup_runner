namespace AcronisBackupTrigger;

public static class HelpContent
{
    public const string Text =
        """
        Acronis Backup Trigger

        Run after the source application's backup:
          AcronisBackupTrigger.exe

        Commands:
          help            Print this guide.
          setup           Configure API client and choose policy/resource (elevated Administrator).
          select-target   Change policy/resource (elevated Administrator; requires REPLACE).
          list-policies   List root protection policies.
          list-resources  List non-group resources attached to the selected policy.
          diagnose        Check configuration, Acronis connectivity, authentication, and target status.
          clear-pending   Clear an ambiguous prior start after checking the Acronis console (elevated Administrator).
          reset           Remove local configuration (elevated Administrator).

        Identity:
          Routine run, diagnose, and discovery require the Configuration administrator identity permitted to read C:\ProgramData\AcronisBackupTrigger.
          setup, select-target, clear-pending, and reset additionally require an elevated Administrator session.

        Safety:
          Exit 12: Acronis accepted the request but running was not observed. Check the console; later runs are not blocked.
          Exit 14: The start outcome is unknown. Check the console. Later runs return 19 until an Administrator runs clear-pending.
          Exit 18: The unattended command exceeded 90 seconds. Check the console before running again.
          Exit 19: A prior start remains outstanding. Check the console, then run clear-pending.

        Release verification:
          Verify SHA256SUMS.txt with Get-FileHash before Unblock-File.
          If endpoint security blocks the unsigned executable, ask client IT for a hash/path allow-list exception.

        Logs:
          C:\ProgramData\AcronisBackupTrigger\trigger.log
        """;
}
