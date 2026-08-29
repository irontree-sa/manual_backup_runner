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
}

public sealed class CommandHost(
    ConfigurationStore store,
    Func<IAcronisTransport> transportFactory,
    TextReader input,
    TextWriter output,
    TextWriter error,
    Func<string> secretReader)
{
    public async Task<int> RunAsync(string[] args, CancellationToken cancellationToken = default)
    {
        var command = args.FirstOrDefault()?.ToLowerInvariant() ?? "run";
        try
        {
            return command switch
            {
                "setup" => Setup(),
                "reset" => Reset(),
                "diagnose" => await DiagnoseAsync(cancellationToken),
                _ => RunUnavailable(),
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

    private int Setup()
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

        store.Save(new TriggerConfiguration(url, clientId, secret));
        output.WriteLine("Configuration saved.");
        return ExitCodes.Success;
    }

    private int Reset()
    {
        store.Reset();
        output.WriteLine("Local configuration removed. Revoke the obsolete API client in Acronis if it is unused elsewhere.");
        return ExitCodes.Success;
    }

    private async Task<int> DiagnoseAsync(CancellationToken cancellationToken)
    {
        var configuration = store.Load();
        if (configuration is null)
        {
            error.WriteLine("Configuration is missing. Run setup first.");
            return ExitCodes.ConfigurationMissing;
        }

        var result = await new Diagnostics(transportFactory()).CheckAsync(configuration, cancellationToken);
        output.WriteLine(result.Outcome);
        return result.Outcome == DiagnosticOutcome.Authenticated ? ExitCodes.Success : ExitCodes.DiagnosticsFailed;
    }

    private int RunUnavailable()
    {
        error.WriteLine("Run is unavailable until a protection policy and Configured resource are selected.");
        return ExitCodes.RunUnavailable;
    }
}
