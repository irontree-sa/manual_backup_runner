using System.Globalization;

namespace BackupPolicyTrigger;

/// <summary>
/// Records that a start request left this machine but its outcome never became known.
/// The marker survives process exit so a later post-backup trigger cannot start a
/// second backup for a request that may already be running.
/// </summary>
public interface IPendingStartStore
{
    DateTimeOffset? Read();
    void Mark(DateTimeOffset sentAt);
    void Clear();
}

public sealed class PendingStartStore(string directory) : IPendingStartStore
{
    private readonly string path = Path.Combine(directory, "pending-start");

    public DateTimeOffset? Read()
    {
        string text;
        try
        {
            text = File.ReadAllText(path);
        }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }

        return DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var sentAt)
            ? sentAt
            : DateTimeOffset.MinValue;
    }

    public void Mark(DateTimeOffset sentAt)
    {
        Directory.CreateDirectory(directory);
        File.WriteAllText(path, sentAt.ToString("o", CultureInfo.InvariantCulture));
    }

    public void Clear()
    {
        if (File.Exists(path)) File.Delete(path);
    }
}
