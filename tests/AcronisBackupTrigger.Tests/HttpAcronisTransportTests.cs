using System.Net;
using AcronisBackupTrigger;

namespace AcronisBackupTrigger.Tests;

public sealed class HttpAcronisTransportTests
{
    private static readonly TriggerConfiguration Config = new("https://example.test", "id", "secret");

    private static HttpResponseMessage TokenResponse() => new(HttpStatusCode.OK)
    {
        Content = new StringContent("""{"access_token":"eyJ0","token_type":"bearer"}"""),
    };

    [Fact]
    public async Task RequestToken_authenticates_when_response_carries_access_token()
    {
        var handler = new StubHandler(_ => TokenResponse());
        using var client = new HttpClient(handler);

        Assert.Equal(TokenResult.Authenticated, await Transport(client).RequestTokenAsync(Config, CancellationToken.None));
        Assert.Equal(1, handler.Attempts);
    }

    [Theory]
    [InlineData("")]
    [InlineData("{}")]
    [InlineData("""{"access_token":""}""")]
    [InlineData("not-json")]
    public async Task RequestToken_rejects_success_without_usable_token(string body)
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) });
        using var client = new HttpClient(handler);

        Assert.Equal(TokenResult.UnexpectedResponse, await Transport(client).RequestTokenAsync(Config, CancellationToken.None));
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, TokenResult.AuthenticationFailed)]
    [InlineData(HttpStatusCode.Forbidden, TokenResult.AuthenticationFailed)]
    [InlineData(HttpStatusCode.NotFound, TokenResult.InvalidDataCenterUrl)]
    [InlineData(HttpStatusCode.MethodNotAllowed, TokenResult.InvalidDataCenterUrl)]
    [InlineData(HttpStatusCode.BadRequest, TokenResult.UnexpectedResponse)]
    public async Task RequestToken_classifies_non_transient_status(HttpStatusCode status, TokenResult expected)
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(status));
        using var client = new HttpClient(handler);

        Assert.Equal(expected, await Transport(client).RequestTokenAsync(Config, CancellationToken.None));
        Assert.Equal(1, handler.Attempts);
    }

    [Fact]
    public async Task RequestToken_posts_documented_token_endpoint_with_basic_credentials()
    {
        var handler = new StubHandler(_ => TokenResponse());
        using var client = new HttpClient(handler);

        await Transport(client).RequestTokenAsync(Config, CancellationToken.None);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("https://example.test/api/2/idp/token", request.Uri);
        Assert.Equal("Basic", request.AuthorizationScheme);
        Assert.Equal(Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes("id:secret")), request.AuthorizationParameter);
        Assert.Equal("grant_type=client_credentials", request.Body);
    }

    [Theory]
    [InlineData("eu2.acronis.cloud")]
    [InlineData("http://eu2.acronis.cloud")]
    [InlineData("https://user:pass@eu2.acronis.cloud")]
    public async Task RequestToken_never_sends_credentials_to_an_unsafe_url(string url)
    {
        var handler = new StubHandler(_ => TokenResponse());
        using var client = new HttpClient(handler);

        var result = await Transport(client).RequestTokenAsync(Config with { DataCenterUrl = url }, CancellationToken.None);

        Assert.Equal(TokenResult.InvalidDataCenterUrl, result);
        Assert.Equal(0, handler.Attempts);
    }

    [Fact]
    public async Task RequestToken_reports_connectivity_failure_after_five_attempts()
    {
        var handler = new StubHandler(_ => throw new HttpRequestException(HttpRequestError.ConnectionError));
        using var client = new HttpClient(handler);
        var delays = new List<TimeSpan>();

        var result = await Transport(client, delays).RequestTokenAsync(Config, CancellationToken.None);

        Assert.Equal(TokenResult.ConnectivityFailed, result);
        Assert.Equal(5, handler.Attempts);
        Assert.Equal([TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(4), TimeSpan.FromSeconds(8), TimeSpan.FromSeconds(16)], delays);
    }

    [Fact]
    public async Task RequestToken_fails_immediately_on_a_non_transient_transport_error()
    {
        var handler = new StubHandler(_ => throw new HttpRequestException(HttpRequestError.SecureConnectionError));
        using var client = new HttpClient(handler);
        var delays = new List<TimeSpan>();

        var result = await Transport(client, delays).RequestTokenAsync(Config, CancellationToken.None);

        Assert.Equal(TokenResult.ConnectivityFailed, result);
        Assert.Equal(1, handler.Attempts);
        Assert.Empty(delays);
    }

    [Theory]
    [InlineData(HttpStatusCode.RequestTimeout)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    public async Task RequestToken_retries_transient_responses(HttpStatusCode status)
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(status));
        using var client = new HttpClient(handler);
        var delays = new List<TimeSpan>();

        var result = await Transport(client, delays).RequestTokenAsync(Config, CancellationToken.None);

        Assert.Equal(TokenResult.AcronisUnavailable, result);
        Assert.Equal(5, handler.Attempts);
        Assert.Equal(4, delays.Count);
    }

    [Fact]
    public async Task RequestToken_retries_a_request_timeout_then_succeeds()
    {
        var handler = new StubHandler(attempt => attempt < 3
            ? throw new TaskCanceledException("timeout")
            : TokenResponse());
        using var client = new HttpClient(handler);
        var delays = new List<TimeSpan>();

        var result = await Transport(client, delays).RequestTokenAsync(Config, CancellationToken.None);

        Assert.Equal(TokenResult.Authenticated, result);
        Assert.Equal(3, handler.Attempts);
        Assert.Equal([TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(4)], delays);
    }

    [Fact]
    public async Task RequestToken_propagates_caller_cancellation()
    {
        var handler = new StubHandler(_ => throw new TaskCanceledException("cancelled"));
        using var client = new HttpClient(handler);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Transport(client).RequestTokenAsync(Config, cancellation.Token));
        Assert.Equal(1, handler.Attempts);
    }

    [Fact]
    public async Task RequestToken_authenticates_once_a_retry_succeeds()
    {
        var handler = new StubHandler(attempt => attempt < 3
            ? new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
            : TokenResponse());
        using var client = new HttpClient(handler);
        var delays = new List<TimeSpan>();

        var result = await Transport(client, delays).RequestTokenAsync(Config, CancellationToken.None);

        Assert.Equal(TokenResult.Authenticated, result);
        Assert.Equal(3, handler.Attempts);
        Assert.Equal([TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(4)], delays);
    }
    [Fact]
    public async Task GetExecutionState_maps_acronis_unavailability_to_connectivity_not_rejection()
    {
        var handler = new StubHandler(attempt => attempt == 1
            ? TokenResponse()
            : new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        using var client = new HttpClient(handler);
        var delays = new List<TimeSpan>();

        var state = await Transport(client, delays).GetExecutionStateAsync(
            Config, "policy-1", "resource-1", CancellationToken.None);

        Assert.Equal(ExecutionState.ConnectivityFailed, state);
        Assert.Equal(6, handler.Attempts);
        Assert.Equal(4, delays.Count);
    }
    [Fact]
    public async Task GetExecutionState_maps_repeated_token_unavailability_to_connectivity_failure()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        using var client = new HttpClient(handler);
        var delays = new List<TimeSpan>();

        var state = await Transport(client, delays).GetExecutionStateAsync(
            Config, "policy-1", "resource-1", CancellationToken.None);

        Assert.Equal(ExecutionState.ConnectivityFailed, state);
        Assert.Equal(5, handler.Attempts);
        Assert.Equal(4, delays.Count);
    }

    [Fact]
    public async Task GetExecutionState_maps_forbidden_state_to_rejection()
    {
        var handler = new StubHandler(attempt => attempt == 1
            ? TokenResponse()
            : new HttpResponseMessage(HttpStatusCode.Forbidden));
        using var client = new HttpClient(handler);
        var delays = new List<TimeSpan>();

        var state = await Transport(client, delays).GetExecutionStateAsync(
            Config, "policy-1", "resource-1", CancellationToken.None);

        Assert.Equal(ExecutionState.AcronisRejected, state);
        Assert.Equal(2, handler.Attempts);
        Assert.Empty(delays);
    }
    [Fact]
    public async Task StartPolicy_puts_the_documented_run_endpoint_with_bearer_and_body()
    {
        var handler = new StubHandler(attempt => attempt == 1
            ? TokenResponse()
            : new HttpResponseMessage(HttpStatusCode.Accepted));
        using var client = new HttpClient(handler);

        await Transport(client).StartPolicyAsync(Config, "policy-1", "resource-1", CancellationToken.None);

        var request = handler.Requests[1];
        Assert.Equal(HttpMethod.Put, request.Method);
        Assert.Equal("https://example.test/api/policy_management/v4/applications/run", request.Uri);
        Assert.Equal("Bearer", request.AuthorizationScheme);
        Assert.Equal("eyJ0", request.AuthorizationParameter);
        Assert.Equal("""{"state":"running","policy_id":"policy-1","context_ids":["resource-1"]}""", request.Body);
    }

    [Theory]
    [InlineData(HttpStatusCode.Accepted, StartOutcome.Accepted)]
    [InlineData(HttpStatusCode.NoContent, StartOutcome.CompletedSynchronously)]
    public async Task StartPolicy_maps_202_and_204(HttpStatusCode status, StartOutcome expected)
    {
        var handler = new StubHandler(attempt => attempt == 1
            ? TokenResponse()
            : new HttpResponseMessage(status));
        using var client = new HttpClient(handler);

        Assert.Equal(expected, await Transport(client).StartPolicyAsync(Config, "policy-1", "resource-1", CancellationToken.None));
        Assert.Equal(2, handler.Attempts);
    }

    [Fact]
    public async Task StartPolicy_maps_401_to_authentication_failure()
    {
        var handler = new StubHandler(attempt => attempt == 1
            ? TokenResponse()
            : new HttpResponseMessage(HttpStatusCode.Unauthorized));
        using var client = new HttpClient(handler);

        Assert.Equal(StartOutcome.AuthenticationFailed, await Transport(client).StartPolicyAsync(Config, "policy-1", "resource-1", CancellationToken.None));
    }

    [Fact]
    public async Task StartPolicy_maps_403_to_rejection_not_authentication_failure()
    {
        var handler = new StubHandler(attempt => attempt == 1
            ? TokenResponse()
            : new HttpResponseMessage(HttpStatusCode.Forbidden));
        using var client = new HttpClient(handler);

        Assert.Equal(StartOutcome.Rejected, await Transport(client).StartPolicyAsync(Config, "policy-1", "resource-1", CancellationToken.None));
    }
    [Fact]
    public async Task StartPolicy_maps_an_undocumented_2xx_to_unexpected_response()
    {
        var handler = new StubHandler(attempt => attempt == 1
            ? TokenResponse()
            : new HttpResponseMessage(HttpStatusCode.OK));
        using var client = new HttpClient(handler);

        Assert.Equal(StartOutcome.UnexpectedResponse, await Transport(client).StartPolicyAsync(Config, "policy-1", "resource-1", CancellationToken.None));
    }

    [Fact]
    public async Task StartPolicy_maps_a_malformed_second_token_response_to_unexpected_response()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("not-json"),
        });
        using var client = new HttpClient(handler);

        Assert.Equal(StartOutcome.UnexpectedResponse, await Transport(client).StartPolicyAsync(Config, "policy-1", "resource-1", CancellationToken.None));
    }

    [Fact]
    public async Task StartPolicy_raises_onSend_only_at_the_put_boundary_and_clears_on_pre_send_failure()
    {
        var handler = new StubHandler(attempt => attempt == 1
            ? TokenResponse()
            : throw new HttpRequestException(HttpRequestError.NameResolutionError));
        using var client = new HttpClient(handler);
        var sends = 0;
        var preSendFailures = 0;

        var result = await Transport(client).StartPolicyAsync(
            Config, "policy-1", "resource-1", CancellationToken.None,
            onSend: () => sends++,
            onPreSendFailure: () => preSendFailures++);

        Assert.Equal(StartOutcome.NotSent, result);
        Assert.Equal(5, sends);
        Assert.Equal(5, preSendFailures);
    }


    [Theory]
    [InlineData(HttpStatusCode.RequestTimeout)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    public async Task StartPolicy_never_resends_an_ambiguous_response(HttpStatusCode status)
    {
        var handler = new StubHandler(attempt => attempt == 1
            ? TokenResponse()
            : new HttpResponseMessage(status));
        using var client = new HttpClient(handler);
        var delays = new List<TimeSpan>();

        var result = await Transport(client, delays).StartPolicyAsync(Config, "policy-1", "resource-1", CancellationToken.None);

        Assert.Equal(StartOutcome.OutcomeUnknown, result);
        Assert.Equal(2, handler.Attempts);
        Assert.Empty(delays);
    }

    [Fact]
    public async Task StartPolicy_never_resends_after_a_timeout()
    {
        var handler = new StubHandler(attempt => attempt == 1
            ? TokenResponse()
            : throw new TaskCanceledException("timeout"));
        using var client = new HttpClient(handler);
        var delays = new List<TimeSpan>();

        var result = await Transport(client, delays).StartPolicyAsync(Config, "policy-1", "resource-1", CancellationToken.None);

        Assert.Equal(StartOutcome.OutcomeUnknown, result);
        Assert.Equal(2, handler.Attempts);
        Assert.Empty(delays);
    }

    [Fact]
    public async Task StartPolicy_propagates_caller_cancellation()
    {
        var handler = new StubHandler(attempt => attempt == 1
            ? TokenResponse()
            : throw new TaskCanceledException("cancelled"));
        using var client = new HttpClient(handler);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Transport(client).StartPolicyAsync(Config, "policy-1", "resource-1", cancellation.Token));
    }

    [Theory]
    [InlineData(HttpRequestError.NameResolutionError)]
    [InlineData(HttpRequestError.SecureConnectionError)]
    [InlineData(HttpRequestError.ProxyTunnelError)]
    public async Task StartPolicy_retries_provably_pre_send_failures_with_bounded_backoff(HttpRequestError error)
    {
        var handler = new StubHandler(attempt => attempt == 1
            ? TokenResponse()
            : throw new HttpRequestException(error));
        using var client = new HttpClient(handler);
        var delays = new List<TimeSpan>();

        var result = await Transport(client, delays).StartPolicyAsync(Config, "policy-1", "resource-1", CancellationToken.None);

        Assert.Equal(StartOutcome.NotSent, result);
        Assert.Equal(6, handler.Attempts);
        Assert.Equal([TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(4), TimeSpan.FromSeconds(8), TimeSpan.FromSeconds(16)], delays);
    }

    [Fact]
    public async Task GetExecutionState_requests_the_documented_status_endpoint_with_filter()
    {
        var handler = new StubHandler(attempt => attempt == 1
            ? TokenResponse()
            : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("""{"items":[]}""") });
        using var client = new HttpClient(handler);

        await Transport(client).GetExecutionStateAsync(Config, "policy-1", "resource-1", CancellationToken.None);

        var request = handler.Requests[1];
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(
            "https://example.test/api/policy_management/v4/applications?policy_id=policy-1&context_id=resource-1&execution_state=running",
            request.Uri);
        Assert.Equal("Bearer", request.AuthorizationScheme);
    }


    private static HttpAcronisTransport Transport(HttpClient client, List<TimeSpan>? delays = null) =>
        new(client, (duration, _) =>
        {
            delays?.Add(duration);
            return Task.CompletedTask;
        });

    private sealed record RecordedRequest(HttpMethod Method, string Uri, string? AuthorizationScheme, string? AuthorizationParameter, string Body);

    private sealed class StubHandler(Func<int, HttpResponseMessage> response) : HttpMessageHandler
    {
        public int Attempts { get; private set; }
        public List<RecordedRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Attempts++;
            Requests.Add(new RecordedRequest(
                request.Method,
                request.RequestUri!.ToString(),
                request.Headers.Authorization?.Scheme,
                request.Headers.Authorization?.Parameter,
                request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken)));
            return response(Attempts);
        }
    }
}
