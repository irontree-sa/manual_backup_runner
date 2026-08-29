using System.Text;

namespace AcronisBackupTrigger;

/// <summary>
/// Appends one sanitized line per event to a bounded log beside the configuration.
/// The calling application may discard our console output, so this file is usually
/// the only record of a failed post-backup trigger.
/// </summary>
public sealed class RotatingLog(
    string directory,
    long maxBytes = 256 * 1024,
    Func<Semaphore>? lockFactory = null)
{
    private readonly string path = Path.Combine(directory, "trigger.log");
    private readonly string previous = Path.Combine(directory, "trigger.log.1");

    // Serialise log writes across processes: the lock-loser path in Program.cs and
    // the command-audit write can otherwise interleave and corrupt the file. The
    // named semaphore is Windows-only; elsewhere a process-local semaphore suffices
    // because the executable targets Windows.
    //
    // The lock is created lazily inside Write rather than in a static field
    // initializer: constructing the named semaphore can fail (unauthorized, I/O, or
    // platform errors), and a static initializer would surface that failure as a
    // TypeInitializationException on first use of the type — outside Write's
    // best-effort boundary. The factory is injectable so tests can simulate a
    // failing or held lock deterministically.
    private readonly Func<Semaphore> _lockFactory = lockFactory ?? CreateDefaultLock;
    private Semaphore? _logLock;

    // A process killed while holding the named semaphore leaves its count at zero
    // forever, so an unbounded WaitOne would deadlock every later command. Wait only
    // briefly; if the lock is held, abandoned, or unavailable, skip this audit line.
    private static readonly TimeSpan LockTimeout = TimeSpan.FromMilliseconds(250);

    private static Semaphore CreateDefaultLock() =>
        OperatingSystem.IsWindows()
            ? new Semaphore(1, 1, "Global\\AcronisBackupTrigger.Log")
            : new Semaphore(1, 1);

    public void Write(string message)
    {
        Semaphore logLock;
        try
        {
            logLock = _logLock ??= _lockFactory();
        }
        catch (Exception ex) when (ex is IOException
            or UnauthorizedAccessException
            or PlatformNotSupportedException
            or TypeInitializationException)
        {
            // Best-effort: a platform that cannot provide the named lock, or a lock
            // that is unavailable, must never change the command result.
            return;
        }

        bool acquired;
        try
        {
            acquired = logLock.WaitOne(LockTimeout);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            // Best-effort: a platform that cannot provide the named lock, or a lock
            // that is unavailable, must never change the command result.
            return;
        }

        if (!acquired)
        {
            // Best-effort: the lock is held (or was abandoned) by another process;
            // skip this audit line rather than block the command.
            return;
        }

        try
        {
            WriteCore(message);
        }
        catch (IOException)
        {
            // Best-effort: a full disk or file lock must never change the command result.
        }
        catch (UnauthorizedAccessException)
        {
            // Best-effort: an unprivileged caller may not write the protected log.
        }
        finally
        {
            logLock.Release();
        }
    }

    private void WriteCore(string message)
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
