using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace AcronisBackupTrigger;

public sealed class HttpAcronisTransport(
    HttpClient client,
    Func<TimeSpan, CancellationToken, Task>? delayOverride = null) : IAcronisTransport
{
    private readonly Func<TimeSpan, CancellationToken, Task> delay =
        delayOverride ?? ((duration, token) => Task.Delay(duration, token));

    private static readonly TimeSpan[] Backoff =
    [
        TimeSpan.FromSeconds(2),
        TimeSpan.FromSeconds(4),
        TimeSpan.FromSeconds(8),
        TimeSpan.FromSeconds(16),
    ];

    public async Task<TokenResult> RequestTokenAsync(TriggerConfiguration configuration, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(configuration.DataCenterUrl, UriKind.Absolute, out var dataCenter)
            || dataCenter.Scheme != Uri.UriSchemeHttps
            || !string.IsNullOrEmpty(dataCenter.UserInfo))
        {
            return TokenResult.InvalidDataCenterUrl;
        }

        var tokenUri = new Uri(new Uri(dataCenter.GetLeftPart(UriPartial.Path).TrimEnd('/') + "/"), "api/2/idp/token");
        var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{configuration.ClientId}:{configuration.ClientSecret}"));

        var lastOutcome = TokenResult.ConnectivityFailed;

        for (var attempt = 0; ; attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, tokenUri)
            {
                Content = new FormUrlEncodedContent([new KeyValuePair<string, string>("grant_type", "client_credentials")]),
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);

            try
            {
                using var response = await client.SendAsync(request, cancellationToken);

                if (response.StatusCode == HttpStatusCode.OK)
                    return await ReadTokenAsync(response, cancellationToken);

                if (!IsTransient(response.StatusCode))
                    return Classify(response.StatusCode);

                lastOutcome = TokenResult.AcronisUnavailable;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                lastOutcome = TokenResult.ConnectivityFailed;
            }
            catch (HttpRequestException exception) when (IsTransient(exception))
            {
                lastOutcome = TokenResult.ConnectivityFailed;
            }
            catch (HttpRequestException)
            {
                return TokenResult.ConnectivityFailed;
            }

            if (attempt >= Backoff.Length) return lastOutcome;
            await delay(Backoff[attempt], cancellationToken);
        }
    }

    private static async Task<TokenResult> ReadTokenAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            await using var body = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var document = await JsonDocument.ParseAsync(body, cancellationToken: cancellationToken);
            return document.RootElement.TryGetProperty("access_token", out var token)
                   && token.ValueKind == JsonValueKind.String
                   && !string.IsNullOrWhiteSpace(token.GetString())
                ? TokenResult.Authenticated
                : TokenResult.UnexpectedResponse;
        }
        catch (JsonException)
        {
            return TokenResult.UnexpectedResponse;
        }
    }

    private static TokenResult Classify(HttpStatusCode status) => status switch
    {
        HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => TokenResult.AuthenticationFailed,
        HttpStatusCode.NotFound or HttpStatusCode.MovedPermanently or HttpStatusCode.Found
            or HttpStatusCode.MethodNotAllowed => TokenResult.InvalidDataCenterUrl,
        _ => TokenResult.UnexpectedResponse,
    };

    private static bool IsTransient(HttpStatusCode status) =>
        status is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests || (int)status >= 500;

    private static bool IsTransient(HttpRequestException exception) => exception.HttpRequestError is
        HttpRequestError.ConnectionError or
        HttpRequestError.NameResolutionError or
        HttpRequestError.ResponseEnded or
        HttpRequestError.Unknown;
}
