using AcronisBackupTrigger;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("This executable must run on Windows.");
    return ExitCodes.UnsupportedPlatform;
}

var directory = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
    "AcronisBackupTrigger");

using var client = new HttpClient();
var host = new CommandHost(
    new ConfigurationStore(directory, new WindowsDpapiProtector()),
    () => new HttpAcronisTransport(client),
    Console.In,
    Console.Out,
    Console.Error,
    ReadSecret);

return await host.RunAsync(args);

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
