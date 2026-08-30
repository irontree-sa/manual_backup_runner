using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace AcronisBackupTrigger;

public sealed class HttpAcronisTransport(
    HttpClient client,
    Func<TimeSpan, CancellationToken, Task>? delayOverride = null) : IAcronisTransport
{
    private const string RootPolicyType = "policy.protection.total";

    /// <summary>Guards against a server that keeps returning a continuation cursor.</summary>
    private const int MaxPages = 50;

    private readonly Func<TimeSpan, CancellationToken, Task> delay =
        delayOverride ?? ((duration, token) => Task.Delay(duration, token));

    private static readonly TimeSpan[] Backoff =
    [
        TimeSpan.FromSeconds(2),
        TimeSpan.FromSeconds(4),
        TimeSpan.FromSeconds(8),
        TimeSpan.FromSeconds(16),
    ];

    public async Task<TokenResult> RequestTokenAsync(TriggerConfiguration configuration, CancellationToken cancellationToken) =>
        (await AcquireTokenAsync(configuration, cancellationToken)).Result;

    public Task<DiscoveryResult<AcronisPolicy>> ListProtectionPoliciesAsync(
        TriggerConfiguration configuration,
        CancellationToken cancellationToken) =>
        ListAsync<AcronisPolicy>(configuration, "api/policy_management/v4/policies?parent_ids=", ReadPolicies, cancellationToken);

    public Task<DiscoveryResult<AcronisResource>> ListResourcesAsync(
        TriggerConfiguration configuration,
        string policyId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyId);
        var path = $"api/resource_management/v4/resources?applied_to_policy_id={Uri.EscapeDataString(policyId)}&is_group=false";
        return ListAsync<AcronisResource>(configuration, path, ReadResources, cancellationToken);
    }

    public async Task<ExecutionState> GetExecutionStateAsync(
        TriggerConfiguration configuration,
        string policyId,
        string resourceId,
        CancellationToken cancellationToken)
    {
        if (!TryResolveDataCenter(configuration, out var dataCenter)) return ExecutionState.ConnectivityFailed;

        var (tokenResult, token) = await AcquireTokenAsync(configuration, cancellationToken);
        if (tokenResult != TokenResult.Authenticated || token is null)
        {
            return tokenResult switch
            {
                TokenResult.AuthenticationFailed => ExecutionState.AuthenticationFailed,
                TokenResult.UnexpectedResponse => ExecutionState.UnexpectedResponse,
                TokenResult.AcronisUnavailable => ExecutionState.ConnectivityFailed,
                _ => ExecutionState.ConnectivityFailed,
            };
        }

        var path = "api/policy_management/v4/applications"
                   + $"?policy_id={Uri.EscapeDataString(policyId)}"
                   + $"&context_id={Uri.EscapeDataString(resourceId)}"
                   + "&execution_state=running";

        var (status, document) = await GetAsync(new Uri(dataCenter, path), token, cancellationToken);
        if (status != DiscoveryStatus.Succeeded || document is null)
        {
            return status switch
            {
                DiscoveryStatus.AuthenticationFailed => ExecutionState.AuthenticationFailed,
                DiscoveryStatus.AcronisRejected => ExecutionState.AcronisRejected,
                DiscoveryStatus.AcronisUnavailable => ExecutionState.ConnectivityFailed,
                DiscoveryStatus.UnexpectedResponse or DiscoveryStatus.InvalidDataCenterUrl => ExecutionState.UnexpectedResponse,
                _ => ExecutionState.ConnectivityFailed,
            };
        }

        using (document)
        {
            if (!document.RootElement.TryGetProperty("items", out var items) || items.ValueKind != JsonValueKind.Array)
                return ExecutionState.UnexpectedResponse;

            return items.GetArrayLength() > 0 ? ExecutionState.Running : ExecutionState.Idle;
        }
    }

    public async Task<StartOutcome> StartPolicyAsync(
        TriggerConfiguration configuration,
        string policyId,
        string resourceId,
        CancellationToken cancellationToken,
        Action? onSend = null,
        Action? onPreSendFailure = null)
    {
        if (!TryResolveDataCenter(configuration, out var dataCenter)) return StartOutcome.NotSent;

        var (tokenResult, token) = await AcquireTokenAsync(configuration, cancellationToken);
        if (tokenResult != TokenResult.Authenticated || token is null)
        {
            return tokenResult switch
            {
                TokenResult.AuthenticationFailed => StartOutcome.AuthenticationFailed,
                TokenResult.UnexpectedResponse => StartOutcome.UnexpectedResponse,
                _ => StartOutcome.NotSent,
            };
        }

        var payload = JsonSerializer.Serialize(new
        {
            state = "running",
            policy_id = policyId,
            context_ids = new[] { resourceId },
        });
        var runUri = new Uri(dataCenter, "api/policy_management/v4/applications/run");

        // Only provably pre-send failures are retried. Once a request may have reached
        // Acronis the outcome is reported as unknown and never resent.
        for (var attempt = 0; ; attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Put, runUri)
            {
                Content = new StringContent(payload, Encoding.UTF8, "application/json"),
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            // The durable pending marker is tied to the actual PUT-send boundary: it is
            // raised only once a request is about to leave this machine, and cleared on
            // every provably pre-send failure so a later unattended run is not blocked.
            onSend?.Invoke();

            try
            {
                using var response = await client.SendAsync(request, cancellationToken);
                return response.StatusCode switch
                {
                    HttpStatusCode.Accepted => StartOutcome.Accepted,
                    HttpStatusCode.NoContent => StartOutcome.CompletedSynchronously,
                    HttpStatusCode.Unauthorized => StartOutcome.AuthenticationFailed,
                    HttpStatusCode.Forbidden => StartOutcome.Rejected,
                    HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests => StartOutcome.OutcomeUnknown,
                    var status when (int)status >= 500 => StartOutcome.OutcomeUnknown,
                    _ => StartOutcome.UnexpectedResponse,
                };
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                // The request may have reached Acronis before the timeout.
                return StartOutcome.OutcomeUnknown;
            }
            catch (HttpRequestException exception) when (IsProvablyPreSend(exception))
            {
                onPreSendFailure?.Invoke();
                if (attempt >= Backoff.Length) return StartOutcome.NotSent;
                await delay(Backoff[attempt], cancellationToken);
            }
            catch (HttpRequestException)
            {
                return StartOutcome.OutcomeUnknown;
            }
        }
    }

    /// <summary>
    /// True only for failures that prove the request never left this machine.
    /// `ConnectionError` is deliberately excluded: a connection can fail after the
    /// request bytes were written, so retrying it could start a second backup.
    /// </summary>
    private static bool IsProvablyPreSend(HttpRequestException exception) => exception.HttpRequestError is
        HttpRequestError.NameResolutionError or
        HttpRequestError.SecureConnectionError or
        HttpRequestError.ProxyTunnelError;

    private async Task<DiscoveryResult<T>> ListAsync<T>(
        TriggerConfiguration configuration,
        string relativePath,
        Action<JsonElement, List<T>> read,
        CancellationToken cancellationToken)
    {
        if (!TryResolveDataCenter(configuration, out var dataCenter))
            return DiscoveryResult<T>.Failed(DiscoveryStatus.InvalidDataCenterUrl);

        var (tokenResult, token) = await AcquireTokenAsync(configuration, cancellationToken);
        if (tokenResult != TokenResult.Authenticated || token is null)
            return DiscoveryResult<T>.Failed(AsDiscoveryStatus(tokenResult));

        var items = new List<T>();
        string? cursor = null;

        for (var page = 0; page < MaxPages; page++)
        {
            var path = cursor is null ? relativePath : $"{relativePath}&after={Uri.EscapeDataString(cursor)}";
            var (status, document) = await GetAsync(new Uri(dataCenter, path), token, cancellationToken);
            if (status != DiscoveryStatus.Succeeded || document is null)
                return DiscoveryResult<T>.Failed(status);

            using (document)
            {
                try
                {
                    read(document.RootElement, items);
                }
                catch (InvalidDataException)
                {
                    return DiscoveryResult<T>.Failed(DiscoveryStatus.UnexpectedResponse);
                }

                cursor = NextCursor(document.RootElement);
            }

            if (cursor is null) return new DiscoveryResult<T>(DiscoveryStatus.Succeeded, items);
        }

        return DiscoveryResult<T>.Failed(DiscoveryStatus.UnexpectedResponse);
    }

    private async Task<(DiscoveryStatus Status, JsonDocument? Document)> GetAsync(
        Uri uri,
        string token,
        CancellationToken cancellationToken)
    {
        var lastStatus = DiscoveryStatus.ConnectivityFailed;

        for (var attempt = 0; ; attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            try
            {
                using var response = await client.SendAsync(request, cancellationToken);

                if (response.StatusCode == HttpStatusCode.OK)
                {
                    try
                    {
                        await using var body = await response.Content.ReadAsStreamAsync(cancellationToken);
                        return (DiscoveryStatus.Succeeded, await JsonDocument.ParseAsync(body, cancellationToken: cancellationToken));
                    }
                    catch (JsonException)
                    {
                        return (DiscoveryStatus.UnexpectedResponse, null);
                    }
                }

                if (!IsTransient(response.StatusCode)) return (ClassifyDiscovery(response.StatusCode), null);
                lastStatus = DiscoveryStatus.AcronisUnavailable;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                lastStatus = DiscoveryStatus.ConnectivityFailed;
            }
            catch (HttpRequestException exception) when (IsTransient(exception))
            {
                lastStatus = DiscoveryStatus.ConnectivityFailed;
            }
            catch (HttpRequestException)
            {
                return (DiscoveryStatus.ConnectivityFailed, null);
            }

            if (attempt >= Backoff.Length) return (lastStatus, null);
            await delay(Backoff[attempt], cancellationToken);
        }
    }

    /// <summary>Returns the continuation cursor, or null when this is the final page.</summary>
    private static string? NextCursor(JsonElement root)
    {
        if (!root.TryGetProperty("paging", out var paging) || paging.ValueKind != JsonValueKind.Object) return null;
        if (!paging.TryGetProperty("cursors", out var cursors) || cursors.ValueKind != JsonValueKind.Object) return null;

        var after = Text(cursors, "after");
        return string.IsNullOrWhiteSpace(after) ? null : after;
    }

    private static JsonElement RequireItems(JsonElement root)
    {
        if (!root.TryGetProperty("items", out var items) || items.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Response does not carry an 'items' array.");

        return items;
    }

    private static void ReadPolicies(JsonElement root, List<AcronisPolicy> policies)
    {
        foreach (var item in RequireItems(root).EnumerateArray())
        {
            if (!item.TryGetProperty("policy", out var composite) || composite.ValueKind != JsonValueKind.Array)
                throw new InvalidDataException("Policy item does not carry a 'policy' array.");

            foreach (var policy in composite.EnumerateArray())
            {
                if (Text(policy, "type") != RootPolicyType) continue;
                if (Text(policy, "id") is not { Length: > 0 } id) continue;

                policies.Add(new AcronisPolicy(id, Text(policy, "name") ?? id));
            }
        }
    }

    private static void ReadResources(JsonElement root, List<AcronisResource> resources)
    {
        foreach (var item in RequireItems(root).EnumerateArray())
        {
            if (Text(item, "id") is not { Length: > 0 } id) continue;

            // Groups such as "All machines" would fan the policy across every member,
            // so refuse them even if the server ignores is_group=false.
            if (item.TryGetProperty("is_group", out var isGroup)
                && isGroup.ValueKind == JsonValueKind.True)
            {
                continue;
            }

            resources.Add(new AcronisResource(id, Text(item, "user_defined_name") ?? Text(item, "name") ?? id));
        }
    }

    private static string? Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private async Task<(TokenResult Result, string? Token)> AcquireTokenAsync(
        TriggerConfiguration configuration,
        CancellationToken cancellationToken)
    {
        if (!TryResolveDataCenter(configuration, out var dataCenter))
            return (TokenResult.InvalidDataCenterUrl, null);

        var tokenUri = new Uri(dataCenter, "api/2/idp/token");
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
                    return (Classify(response.StatusCode), null);

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
                return (TokenResult.ConnectivityFailed, null);
            }

            if (attempt >= Backoff.Length) return (lastOutcome, null);
            await delay(Backoff[attempt], cancellationToken);
        }
    }

    private static bool TryResolveDataCenter(TriggerConfiguration configuration, out Uri dataCenter)
    {
        dataCenter = null!;
        if (!Uri.TryCreate(configuration.DataCenterUrl, UriKind.Absolute, out var parsed)
            || parsed.Scheme != Uri.UriSchemeHttps
            || !string.IsNullOrEmpty(parsed.UserInfo))
        {
            return false;
        }

        dataCenter = new Uri(parsed.GetLeftPart(UriPartial.Path).TrimEnd('/') + "/");
        return true;
    }

    private static async Task<(TokenResult Result, string? Token)> ReadTokenAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var body = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var document = await JsonDocument.ParseAsync(body, cancellationToken: cancellationToken);
            var token = Text(document.RootElement, "access_token");
            return string.IsNullOrWhiteSpace(token)
                ? (TokenResult.UnexpectedResponse, null)
                : (TokenResult.Authenticated, token);
        }
        catch (JsonException)
        {
            return (TokenResult.UnexpectedResponse, null);
        }
    }

    private static DiscoveryStatus AsDiscoveryStatus(TokenResult result) => result switch
    {
        TokenResult.Authenticated => DiscoveryStatus.Succeeded,
        TokenResult.AuthenticationFailed => DiscoveryStatus.AuthenticationFailed,
        TokenResult.InvalidDataCenterUrl => DiscoveryStatus.InvalidDataCenterUrl,
        TokenResult.AcronisUnavailable => DiscoveryStatus.AcronisUnavailable,
        TokenResult.UnexpectedResponse => DiscoveryStatus.UnexpectedResponse,
        _ => DiscoveryStatus.ConnectivityFailed,
    };

    private static TokenResult Classify(HttpStatusCode status) => status switch
    {
        HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => TokenResult.AuthenticationFailed,
        HttpStatusCode.NotFound or HttpStatusCode.MovedPermanently or HttpStatusCode.Found
            or HttpStatusCode.MethodNotAllowed => TokenResult.InvalidDataCenterUrl,
        _ => TokenResult.UnexpectedResponse,
    };

    /// <summary>
    /// Discovery runs with a valid token, so 403 means the API client lacks the
    /// required read permission rather than that authentication failed.
    /// </summary>
    private static DiscoveryStatus ClassifyDiscovery(HttpStatusCode status) => status switch
    {
        HttpStatusCode.Unauthorized => DiscoveryStatus.AuthenticationFailed,
        HttpStatusCode.Forbidden => DiscoveryStatus.AcronisRejected,
        HttpStatusCode.NotFound or HttpStatusCode.MovedPermanently or HttpStatusCode.Found
            or HttpStatusCode.MethodNotAllowed => DiscoveryStatus.InvalidDataCenterUrl,
        _ => DiscoveryStatus.UnexpectedResponse,
    };

    private static bool IsTransient(HttpStatusCode status) =>
        status is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests || (int)status >= 500;

    private static bool IsTransient(HttpRequestException exception) => exception.HttpRequestError is
        HttpRequestError.ConnectionError or
        HttpRequestError.NameResolutionError or
        HttpRequestError.ResponseEnded or
        HttpRequestError.Unknown;
}
