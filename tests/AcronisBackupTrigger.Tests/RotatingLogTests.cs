using System.Diagnostics;
using AcronisBackupTrigger;

namespace AcronisBackupTrigger.Tests;

public sealed class RotatingLogTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));

    // A single shared semaphore injected into every RotatingLog under test, so
    // holding it here simulates another process (or a killed process that abandoned
    // the lock) without needing a second executable.
    private readonly Semaphore logLock = new(1, 1);

    [Fact]
    public void Write_skips_the_audit_line_when_the_lock_is_held()
    {
        var log = new RotatingLog(directory, lockFactory: () => logLock);

        logLock.WaitOne();
        try
        {
            log.Write("run: exit=0 outcome=ObservedRunning");
        }
        finally
        {
            logLock.Release();
        }

        Assert.False(File.Exists(Path.Combine(directory, "trigger.log")),
            "a held lock must skip the write, not queue it");
    }

    [Fact]
    public void Write_returns_promptly_when_the_lock_is_held()
    {
        var log = new RotatingLog(directory, lockFactory: () => logLock);

        logLock.WaitOne();
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
            logLock.Release();
        }
    }

    [Fact]
    public void Write_serializes_concurrent_writes_without_corruption()
    {
        var log = new RotatingLog(directory, maxBytes: 64 * 1024, lockFactory: () => logLock);

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

    [Fact]
    public void Write_skips_the_audit_line_when_lock_creation_fails()
    {
        var log = new RotatingLog(directory, lockFactory: () => throw new UnauthorizedAccessException("denied"));

        log.Write("run: exit=0 outcome=ObservedRunning");

        Assert.False(File.Exists(Path.Combine(directory, "trigger.log")),
            "a lock that cannot be created must skip the write, not throw");
    }

    [Fact]
    public void Write_skips_the_audit_line_when_lock_creation_throws_type_initialization()
    {
        // A static initializer failure surfaces as TypeInitializationException; the
        // lazy factory must treat it as a skipped audit line, not a crash.
        var log = new RotatingLog(directory, lockFactory: () => throw new TypeInitializationException(
            "RotatingLog", new UnauthorizedAccessException("denied")));

        log.Write("run: exit=0 outcome=ObservedRunning");

        Assert.False(File.Exists(Path.Combine(directory, "trigger.log")),
            "a wrapped lock-creation failure must skip the write, not throw");
    }

    [Fact]
    public void Write_skips_the_audit_line_when_named_semaphore_cannot_be_opened()
    {
        // A named semaphore whose name collides with an existing kernel object of a
        // different type surfaces as WaitHandleCannotBeOpenedException; the lazy
        // factory must treat it as a skipped audit line, not a crash.
        var log = new RotatingLog(directory, lockFactory: () => throw new WaitHandleCannotBeOpenedException("type mismatch"));

        log.Write("run: exit=0 outcome=ObservedRunning");

        Assert.False(File.Exists(Path.Combine(directory, "trigger.log")),
            "a named semaphore that cannot be opened must skip the write, not throw");
    }

    [Fact]
    public void Write_swallows_semaphore_full_exception_when_release_fails()
    {
        var semaphore = new Semaphore(1, 1);
        var log = new RotatingLog(directory, lockFactory: () => semaphore);

        // A background thread waits for Write to acquire the lock (count drops to
        // 0), then releases it once so Write's own Release() finds the count already
        // at its maximum and throws SemaphoreFullException.
        var releaser = Task.Run(() =>
        {
            while (semaphore.WaitOne(0))
                semaphore.Release();
            semaphore.Release();
        });

        log.Write("run: exit=0 outcome=ObservedRunning");

        releaser.Wait();
        Assert.True(File.Exists(Path.Combine(directory, "trigger.log")),
            "a release failure must not prevent the audit line from being written");
    }

    public void Dispose()
    {
        logLock.Dispose();
        if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }
}
