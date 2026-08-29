namespace AcronisBackupTrigger;

public static class ExitCodes
{
    public const int Success = 0;
    public const int UnsupportedPlatform = 2;
    public const int ConfigurationMissing = 3;
    public const int DiagnosticsFailed = 4;
    public const int RunUnavailable = 5;
    public const int ConfigurationInaccessible = 6;
    public const int ConfigurationUnreadable = 7;
    public const int InternalError = 8;
    public const int DiscoveryFailed = 9;
    public const int SelectionInvalid = 10;
    public const int AlreadyRunning = 11;
    public const int AcceptedNotObserved = 12;
    public const int AcronisRejected = 13;
    public const int StartOutcomeUnknown = 14;
    public const int RunAuthenticationFailed = 15;
    public const int RunConnectivityFailed = 16;
    public const int UnknownCommand = 17;
    public const int TotalTimeout = 18;
    public const int StartOutstanding = 19;
    public const int UnexpectedResponse = 20;
}

public sealed class CommandHost(
    ConfigurationStore store,
    Func<IAcronisTransport> transportFactory,
    TextReader input,
    TextWriter output,
    TextWriter error,
    Func<string> secretReader,
    Func<IAcronisTransport, BackupTrigger>? triggerFactory = null,
    Action<string>? log = null,
    IPendingStartStore? pendingStarts = null)
{
    private readonly IPendingStartStore pending = pendingStarts ?? new NullPendingStartStore();

    public async Task<int> RunAsync(string[] args, CancellationToken cancellationToken = default)
    {
        var requested = args.FirstOrDefault()?.ToLowerInvariant() ?? "run";
        var command = Known.Contains(requested) ? requested : "unknown";
        var exit = await DispatchAsync(requested, command, cancellationToken);

        // Log the recognised command name only: an unknown argument may contain secrets.
        log?.Invoke($"{command}: exit={exit}");
        return exit;
    }

    private static readonly HashSet<string> Known =
        ["setup", "reset", "select-target", "diagnose", "list-policies", "list-resources", "run", "clear-pending", "help"];

    private int Help()
    {
        output.WriteLine(HelpContent.Text);
        return ExitCodes.Success;
    }

    private async Task<int> DispatchAsync(string requested, string command, CancellationToken cancellationToken)
    {
        try
        {
            return command switch
            {
                "setup" => await SetupAsync(cancellationToken),
                "reset" => Reset(),
                "select-target" => await SelectTargetAsync(cancellationToken),
                "diagnose" => await DiagnoseAsync(cancellationToken),
                "list-policies" => await ListPoliciesAsync(cancellationToken),
                "list-resources" => await ListResourcesAsync(cancellationToken),
                "run" => await TriggerBackupAsync(cancellationToken),
                "clear-pending" => ClearPending(),
                "help" => Help(),
                _ => UnknownCommand(),
            };
        }
        catch (UnauthorizedAccessException)
        {
            error.WriteLine("Configuration is not accessible to this account.");
            return ExitCodes.ConfigurationInaccessible;
        }
        catch (ConfigurationUnreadableException exception)
        {
            error.WriteLine($"{exception.Message} Run setup to reconfigure.");
            return ExitCodes.ConfigurationUnreadable;
        }
        catch (IOException)
        {
            error.WriteLine("Configuration storage is unavailable on this machine.");
            return ExitCodes.InternalError;
        }
    }

    private async Task<int> SetupAsync(CancellationToken cancellationToken)
    {
        TriggerConfiguration? existing;
        try
        {
            existing = store.Load();
        }
        catch (ConfigurationUnreadableException)
        {
            output.WriteLine("Existing configuration cannot be read and will be replaced.");
            existing = null;
        }

        if (existing is not null)
        {
            output.WriteLine($"Current configuration: {existing.DataCenterUrl} / {existing.ClientId}");
            if (existing.PolicyId is not null)
                output.WriteLine($"Current target: {existing.PolicyName} ({existing.PolicyId}) on {existing.ResourceName} ({existing.ResourceId})");

            output.Write("Type REPLACE to overwrite it: ");
            if (!string.Equals(input.ReadLine(), "REPLACE", StringComparison.Ordinal))
            {
                output.WriteLine("Configuration unchanged.");
                return ExitCodes.Success;
            }
        }

        output.Write("Acronis data-centre URL: ");
        var url = input.ReadLine() ?? "";
        output.Write("API client ID: ");
        var clientId = input.ReadLine() ?? "";
        output.Write("API client secret: ");
        var secret = secretReader();
        output.WriteLine();

        var credentials = new TriggerConfiguration(url, clientId, secret);
        return await ChooseAndSaveTargetAsync(credentials, cancellationToken);
    }

    private async Task<int> SelectTargetAsync(CancellationToken cancellationToken)
    {
        if (Required() is not { } configuration) return ExitCodes.ConfigurationMissing;

        if (configuration.PolicyId is not null)
        {
            output.WriteLine($"Current target: {configuration.PolicyName} ({configuration.PolicyId}) on {configuration.ResourceName} ({configuration.ResourceId})");
            output.Write("Type REPLACE to choose a different target: ");
            if (!string.Equals(input.ReadLine(), "REPLACE", StringComparison.Ordinal))
            {
                output.WriteLine("Target unchanged.");
                return ExitCodes.Success;
            }
        }

        return await ChooseAndSaveTargetAsync(configuration, cancellationToken);
    }

    private async Task<int> ChooseAndSaveTargetAsync(TriggerConfiguration credentials, CancellationToken cancellationToken)
    {
        var transport = transportFactory();

        var policies = await transport.ListProtectionPoliciesAsync(credentials, cancellationToken);
        if (policies.Status != DiscoveryStatus.Succeeded) return ReportDiscoveryFailure("protection policies", policies.Status);
        if (policies.Items.Count == 0)
        {
            error.WriteLine("This tenant exposes no root protection policy for this API client.");
            return ExitCodes.SelectionInvalid;
        }

        if (Select("protection policy", policies.Items, p => $"{p.Name} ({p.Id})") is not { } policy)
            return ExitCodes.SelectionInvalid;

        var resources = await transport.ListResourcesAsync(credentials, policy.Id, cancellationToken);
        if (resources.Status != DiscoveryStatus.Succeeded) return ReportDiscoveryFailure("protected resources", resources.Status);
        if (resources.Items.Count == 0)
        {
            error.WriteLine($"Protection policy {policy.Name} has no protected resource attached.");
            return ExitCodes.SelectionInvalid;
        }

        if (Select("protected resource", resources.Items, r => $"{r.Name} ({r.Id})") is not { } resource)
            return ExitCodes.SelectionInvalid;

        store.Save(credentials with
        {
            PolicyId = policy.Id,
            PolicyName = policy.Name,
            ResourceId = resource.Id,
            ResourceName = resource.Name,
        });

        output.WriteLine($"Configuration saved. Target: {policy.Name} ({policy.Id}) on {resource.Name} ({resource.Id}).");
        return ExitCodes.Success;
    }

    private T? Select<T>(string label, IReadOnlyList<T> items, Func<T, string> describe) where T : class
    {
        output.WriteLine($"Available {label} options:");
        for (var index = 0; index < items.Count; index++)
            output.WriteLine($"  {index + 1}. {describe(items[index])}");

        output.Write($"Select a {label} by number: ");
        var answer = input.ReadLine();
        if (int.TryParse(answer, out var choice) && choice >= 1 && choice <= items.Count)
            return items[choice - 1];

        error.WriteLine($"'{answer}' is not one of the offered {label} options. Configuration unchanged.");
        return null;
    }

    private int Reset()
    {
        store.Reset();
        output.WriteLine("Local configuration removed. Revoke the obsolete API client in Acronis if it is unused elsewhere.");
        return ExitCodes.Success;
    }

    private async Task<int> DiagnoseAsync(CancellationToken cancellationToken)
    {
        if (Required() is not { } configuration) return ExitCodes.ConfigurationMissing;

        var result = await new Diagnostics(transportFactory()).CheckAsync(configuration, cancellationToken);
        output.WriteLine(result.Outcome);

        if (result.Outcome != DiagnosticOutcome.Authenticated) return ExitCodes.DiagnosticsFailed;

        if (configuration.PolicyId is null)
        {
            output.WriteLine("No protection policy is selected. Run setup to choose a target.");
            return ExitCodes.Success;
        }

        output.WriteLine($"Target: {configuration.PolicyName} ({configuration.PolicyId}) on {configuration.ResourceName} ({configuration.ResourceId}).");
        return ExitCodes.Success;
    }

    private async Task<int> ListPoliciesAsync(CancellationToken cancellationToken)
    {
        if (Required() is not { } configuration) return ExitCodes.ConfigurationMissing;

        var policies = await transportFactory().ListProtectionPoliciesAsync(configuration, cancellationToken);
        if (policies.Status != DiscoveryStatus.Succeeded) return ReportDiscoveryFailure("protection policies", policies.Status);

        output.WriteLine("Protection policies:");
        foreach (var policy in policies.Items) output.WriteLine($"  {policy.Name} ({policy.Id})");
        if (policies.Items.Count == 0) output.WriteLine("  none");
        return ExitCodes.Success;
    }

    private async Task<int> ListResourcesAsync(CancellationToken cancellationToken)
    {
        if (Required() is not { } configuration) return ExitCodes.ConfigurationMissing;

        if (configuration.PolicyId is null)
        {
            error.WriteLine("No protection policy is configured. Run setup to select one.");
            return ExitCodes.ConfigurationMissing;
        }

        var resources = await transportFactory().ListResourcesAsync(configuration, configuration.PolicyId, cancellationToken);
        if (resources.Status != DiscoveryStatus.Succeeded) return ReportDiscoveryFailure("protected resources", resources.Status);

        output.WriteLine($"Protected resources for {configuration.PolicyName} ({configuration.PolicyId}):");
        foreach (var resource in resources.Items) output.WriteLine($"  {resource.Name} ({resource.Id})");
        if (resources.Items.Count == 0) output.WriteLine("  none");
        return ExitCodes.Success;
    }

    private TriggerConfiguration? Required()
    {
        var configuration = store.Load();
        if (configuration is not null) return configuration;

        error.WriteLine("Configuration is missing. Run setup first.");
        return null;
    }

    private int ReportDiscoveryFailure(string subject, DiscoveryStatus status)
    {
        error.WriteLine($"Unable to list {subject}: {status}.");
        return ExitCodes.DiscoveryFailed;
    }

    private async Task<int> TriggerBackupAsync(CancellationToken cancellationToken)
    {
        if (Required() is not { } configuration) return ExitCodes.ConfigurationMissing;

        var transport = transportFactory();
        var trigger = triggerFactory?.Invoke(transport) ?? new BackupTrigger(transport, pending);

        TriggerResult result;
        try
        {
            result = await trigger.RunAsync(configuration, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            error.WriteLine("The run exceeded its time budget. Check the Acronis console before running again.");
            return ExitCodes.TotalTimeout;
        }

        var exit = result.Outcome switch
        {
            TriggerOutcome.ObservedRunning or TriggerOutcome.CompletedSynchronously => ExitCodes.Success,
            TriggerOutcome.AlreadyRunning => ExitCodes.AlreadyRunning,
            TriggerOutcome.AcceptedNotObserved => ExitCodes.AcceptedNotObserved,
            TriggerOutcome.TargetNotConfigured => ExitCodes.RunUnavailable,
            TriggerOutcome.AuthenticationFailed => ExitCodes.RunAuthenticationFailed,
            TriggerOutcome.ConnectivityFailed => ExitCodes.RunConnectivityFailed,
            TriggerOutcome.AcronisRejected => ExitCodes.AcronisRejected,
            TriggerOutcome.StartOutstanding => ExitCodes.StartOutstanding,
            TriggerOutcome.UnexpectedResponse => ExitCodes.UnexpectedResponse,
            TriggerOutcome.TotalTimeout => ExitCodes.TotalTimeout,
            _ => ExitCodes.StartOutcomeUnknown,
        };

        var line = $"{result.Outcome}: {result.Detail}";
        if (exit == ExitCodes.Success) output.WriteLine(line);
        else error.WriteLine(line);

        return exit;
    }

    private int ClearPending()
    {
        if (pending.Read() is not { } sentAt)
        {
            output.WriteLine("No outstanding start request is recorded.");
            return ExitCodes.Success;
        }

        pending.Clear();
        output.WriteLine($"Cleared the outstanding start request recorded at {sentAt:u}. Confirm in the Acronis console that no backup is still running.");
        return ExitCodes.Success;
    }

    private int UnknownCommand()
    {
        error.WriteLine("Unknown command. Use setup, select-target, list-policies, list-resources, diagnose, clear-pending, reset, or no argument to run.");
        return ExitCodes.UnknownCommand;
    }
}

/// <summary>Used when no durable pending-start location is configured, e.g. in tests.</summary>
public sealed class NullPendingStartStore : IPendingStartStore
{
    public DateTimeOffset? Read() => null;
    public void Mark(DateTimeOffset sentAt) { }
    public void Clear() { }
}
