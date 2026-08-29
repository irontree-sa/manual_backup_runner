using System.Diagnostics;
using System.Reflection;
using AcronisBackupTrigger;

namespace AcronisBackupTrigger.Tests;

public sealed class RotatingLogTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));

    // The named semaphore is a single static shared by every RotatingLog instance in
    // the process, so holding it here simulates another process (or a killed process
    // that abandoned the lock) without needing a second executable.
    private static readonly Semaphore LogLock = (Semaphore)typeof(RotatingLog)
        .GetField("LogLock", BindingFlags.NonPublic | BindingFlags.Static)!
        .GetValue(null)!;

    [Fact]
    public void Write_skips_the_audit_line_when_the_lock_is_held()
    {
        var log = new RotatingLog(directory);

        LogLock.WaitOne();
        try
        {
            log.Write("run: exit=0 outcome=ObservedRunning");
        }
        finally
        {
            LogLock.Release();
        }

        Assert.False(File.Exists(Path.Combine(directory, "trigger.log")),
            "a held lock must skip the write, not queue it");
    }

    [Fact]
    public void Write_returns_promptly_when_the_lock_is_held()
    {
        var log = new RotatingLog(directory);

        LogLock.WaitOne();
        try
        {
            var stopwatch = Stopwatch.StartNew();
            log.Write("run: exit=0 outcome=ObservedRunning");
            stopwatch.Stop();

            // The bounded wait is 250 ms; allow generous scheduling slack but prove
            // the call does not block indefinitely on an abandoned lock.
            Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5),
                $"Write blocked for {stopwatch.Elapsed} on a held lock");
        }
        finally
        {
            LogLock.Release();
        }
    }

    [Fact]
    public void Write_serializes_concurrent_writes_without_corruption()
    {
        var log = new RotatingLog(directory, maxBytes: 64 * 1024);

        var writers = Enumerable.Range(0, 8)
            .Select(i => Task.Run(() =>
            {
                for (var n = 0; n < 50; n++)
                    log.Write($"writer {i} entry {n}");
            }))
            .ToArray();

        Task.WaitAll(writers);

        var lines = File.ReadAllLines(Path.Combine(directory, "trigger.log"));
        Assert.Equal(8 * 50, lines.Length);
        Assert.All(lines, line => Assert.Matches(@"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z writer \d+ entry \d+$", line));
    }

    public void Dispose()
    {
        if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }
}
