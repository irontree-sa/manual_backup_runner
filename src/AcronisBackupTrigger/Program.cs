using System.Diagnostics;
using AcronisBackupTrigger;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("This executable must run on Windows.");
    return ExitCodes.UnsupportedPlatform;
}

// The whole invocation is bounded, including lock acquisition: the calling
// application's post-backup hook must not hang on Acronis.
var totalBudget = TimeSpan.FromSeconds(90);
var invocation = Stopwatch.StartNew();

var directory = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
    "AcronisBackupTrigger");

var log = new RotatingLog(directory);
var pendingStarts = new PendingStartStore(directory);

// Serialise state-check-then-start on this machine so two post-backup hooks firing
// together cannot both decide the policy is idle. A named semaphore is used rather
// than a mutex because mutex ownership is thread-affine and this work continues on
// a different thread after each await.
using var machineLock = new Semaphore(1, 1, "Global\\AcronisBackupTrigger");
if (!machineLock.WaitOne(TimeSpan.FromSeconds(20)))
{
    Console.Error.WriteLine("Another Acronis Backup Trigger run is in progress on this machine.");
    log.Write("run: refused, another instance holds the machine lock");
    return ExitCodes.AlreadyRunning;
}

// Interactive administration waits on a human, so only the unattended commands
// carry the invocation budget.
var interactive = args.FirstOrDefault()?.ToLowerInvariant() is "setup" or "select-target";

try
{
    CancellationTokenSource? budget = null;
    if (!interactive)
    {
        var remaining = totalBudget - invocation.Elapsed;
        if (remaining <= TimeSpan.Zero)
        {
            Console.Error.WriteLine("The run exceeded its time budget before starting. Nothing was requested.");
            log.Write("run: budget exhausted before dispatch");
            return ExitCodes.TotalTimeout;
        }

        budget = new CancellationTokenSource(remaining);
    }

    using (budget)
    {
        using var client = new HttpClient();

        var host = new CommandHost(
            new ConfigurationStore(directory, new WindowsDpapiProtector()),
            () => new HttpAcronisTransport(client),
            Console.In,
            Console.Out,
            Console.Error,
            ReadSecret,
            log: log.Write,
            pendingStarts: pendingStarts);

        return await host.RunAsync(args, budget?.Token ?? CancellationToken.None);
    }
}
finally
{
    machineLock.Release();
}

static string ReadSecret()
{
    if (Console.IsInputRedirected) return Console.ReadLine() ?? "";

    var value = new System.Text.StringBuilder();
    ConsoleKeyInfo key;
    while ((key = Console.ReadKey(intercept: true)).Key != ConsoleKey.Enter)
    {
        if (key.Key == ConsoleKey.Backspace && value.Length > 0) value.Length--;
        else if (!char.IsControl(key.KeyChar)) value.Append(key.KeyChar);
    }
    return value.ToString();
}
