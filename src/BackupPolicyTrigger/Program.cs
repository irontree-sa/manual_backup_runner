using System.Diagnostics;
using BackupPolicyTrigger;

// Help is static and secret-free, so it must be available before any runtime
// dependency: the Windows platform guard, configuration, logging, the machine
// lock, transport, and elevation checks. It deliberately bypasses command-audit
// logging because the restricted log path may be unwritable to an unprivileged
// caller.
if (args.Length == 1 && string.Equals(args[0], "help", StringComparison.OrdinalIgnoreCase))
{
    Console.Out.WriteLine(HelpContent.Text);
    return ExitCodes.Success;
}

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
    "BackupPolicyTrigger");

var setupRequested = args.FirstOrDefault()?.Equals("setup", StringComparison.OrdinalIgnoreCase) == true;

return await new StartupSynchronizationGate().ExecuteAsync(
    new StartupSynchronizationRequest(
        directory,
        setupRequested,
        TimeSpan.FromSeconds(20),
        new ConfigurationStoreAdapter(directory),
        new SynchronizationMetadataStoreAdapter(directory),
        new NamedSemaphoreFactoryAdapter(),
        new WindowsAdministratorGate(),
        new WindowsConfigurationAdministratorIdentity()),
    async () =>
    {
        var log = new RotatingLog(directory);
        var pendingStarts = new PendingStartStore(directory);

        // Interactive administration waits on a human, so only the unattended
        // commands carry the invocation budget.
        var interactive = args.FirstOrDefault()?.ToLowerInvariant() is "setup" or "select-target";

        CancellationTokenSource? budget = null;
        if (!interactive)
        {
            var remaining = totalBudget - invocation.Elapsed;
            if (remaining <= TimeSpan.Zero)
            {
                Console.Error.WriteLine("The run exceeded its time budget before starting. Nothing was requested.");
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
                new Trigger(
                    () => new HttpAcronisTransport(client),
                    pendingStarts,
                    log.Write,
                    Console.Out,
                    Console.Error),
                pendingStarts: pendingStarts,
                administratorGate: new WindowsAdministratorGate());
            return await host.RunAsync(args, budget?.Token ?? CancellationToken.None);
        }
    },
    Console.Error);

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
