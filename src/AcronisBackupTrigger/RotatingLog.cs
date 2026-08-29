using System.Text;

namespace AcronisBackupTrigger;

/// <summary>
/// Appends one sanitized line per event to a bounded log beside the configuration.
/// The calling application may discard our console output, so this file is usually
/// the only record of a failed post-backup trigger.
/// </summary>
public sealed class RotatingLog(string directory, long maxBytes = 256 * 1024)
{
    private readonly string path = Path.Combine(directory, "trigger.log");
    private readonly string previous = Path.Combine(directory, "trigger.log.1");

    public void Write(string message)
    {
        Directory.CreateDirectory(directory);

        var line = $"{DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ssZ} {Sanitize(message)}{Environment.NewLine}";
        var bytes = Encoding.UTF8.GetByteCount(line);

        // A single line must never exceed the bound, or rotation could not hold it.
        if (bytes > maxBytes)
        {
            line = $"{DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ssZ} [truncated event]{Environment.NewLine}";
            bytes = Encoding.UTF8.GetByteCount(line);
        }

        Rotate(bytes);
        File.AppendAllText(path, line, Encoding.UTF8);
    }

    private void Rotate(int incomingBytes)
    {
        var current = new FileInfo(path);
        if (!current.Exists || current.Length + incomingBytes <= maxBytes) return;

        if (File.Exists(previous)) File.Delete(previous);
        File.Move(path, previous);
    }

    /// <summary>
    /// Collapses whitespace so one event stays one line, and refuses anything that
    /// looks like credential material.
    /// </summary>
    private static string Sanitize(string message)
    {
        var single = message.ReplaceLineEndings(" ");
        foreach (var forbidden in (string[])["bearer ", "basic ", "access_token", "client_secret", "eyj"])
        {
            if (single.Contains(forbidden, StringComparison.OrdinalIgnoreCase))
                return "[redacted: message contained credential material]";
        }

        return single;
    }
}
