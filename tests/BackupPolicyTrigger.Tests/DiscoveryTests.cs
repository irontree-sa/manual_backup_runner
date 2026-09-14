using System.Net;
using BackupPolicyTrigger;

namespace BackupPolicyTrigger.Tests;

public sealed class DiscoveryTests
{
    private static readonly TriggerConfiguration Config = new("https://example.test", "id", "secret");

    private const string TokenBody = """{"access_token":"eyJ0","token_type":"bearer"}""";

    private const string PolicyBody = """
    {
      "items": [
        { "policy": [
            { "id": "11111111-1111-1111-1111-111111111111", "name": "Servers daily", "type": "policy.protection.total", "enabled": true },
            { "id": "22222222-2222-2222-2222-222222222222", "name": "child", "type": "policy.backup.machine", "enabled": true }
        ] },
        { "policy": [
            { "id": "33333333-3333-3333-3333-333333333333", "name": "SQL hourly", "type": "policy.protection.total", "enabled": true }
        ] }
      ]
    }
    """;

    private const string ResourceBody = """
    {
      "items": [
        { "id": "44444444-4444-4444-4444-444444444444", "name": "DESKTOP-A", "type": "resource.machine" },
        { "id": "55555555-5555-5555-5555-555555555555", "name": "SQL-01", "user_defined_name": "SQL-01 (prod)", "type": "resource.machine" }
      ]
    }
    """;

    [Fact]
    public async Task ListProtectionPolicies_returns_only_root_protection_policies()
    {
        var handler = new RouteHandler();
        using var client = new HttpClient(handler);

        var result = await Transport(client).ListProtectionPoliciesAsync(Config, CancellationToken.None);

        Assert.Equal(DiscoveryStatus.Succeeded, result.Status);
        Assert.Equal(
            [new AcronisPolicy("11111111-1111-1111-1111-111111111111", "Servers daily"),
             new AcronisPolicy("33333333-3333-3333-3333-333333333333", "SQL hourly")],
            result.Items);
    }

    [Fact]
    public async Task ListProtectionPolicies_requests_the_documented_policy_endpoint_with_bearer_token()
    {
        var handler = new RouteHandler();
        using var client = new HttpClient(handler);

        await Transport(client).ListProtectionPoliciesAsync(Config, CancellationToken.None);

        var request = handler.Requests[^1];
        Assert.StartsWith("https://example.test/api/policy_management/v4/policies", request.Uri);
        Assert.Equal("Bearer", request.AuthorizationScheme);
        Assert.Equal("eyJ0", request.AuthorizationParameter);
    }

    [Fact]
    public async Task ListResources_returns_resources_attached_to_the_selected_policy()
    {
        var handler = new RouteHandler();
        using var client = new HttpClient(handler);

        var result = await Transport(client).ListResourcesAsync(Config, "11111111-1111-1111-1111-111111111111", CancellationToken.None);

        Assert.Equal(DiscoveryStatus.Succeeded, result.Status);
        Assert.Equal(
            [new AcronisResource("44444444-4444-4444-4444-444444444444", "DESKTOP-A"),
             new AcronisResource("55555555-5555-5555-5555-555555555555", "SQL-01 (prod)")],
            result.Items);
        Assert.Contains("applied_to_policy_id=11111111-1111-1111-1111-111111111111", handler.Requests[^1].Uri);
        Assert.Contains("is_group=false", handler.Requests[^1].Uri);
    }

    [Fact]
    public async Task ListResources_returns_no_items_when_the_policy_has_no_attached_resource()
    {
        var handler = new RouteHandler { ResourceBody = """{"items":[]}""" };
        using var client = new HttpClient(handler);

        var result = await Transport(client).ListResourcesAsync(Config, "11111111-1111-1111-1111-111111111111", CancellationToken.None);

        Assert.Equal(DiscoveryStatus.Succeeded, result.Status);
        Assert.Empty(result.Items);
    }

    [Fact]
    public async Task Discovery_reports_authentication_failure_without_requesting_policies()
    {
        var handler = new RouteHandler { TokenStatus = HttpStatusCode.Unauthorized };
        using var client = new HttpClient(handler);

        var result = await Transport(client).ListProtectionPoliciesAsync(Config, CancellationToken.None);

        Assert.Equal(DiscoveryStatus.AuthenticationFailed, result.Status);
        Assert.Empty(result.Items);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task Discovery_reports_unexpected_response_for_malformed_json()
    {
        var handler = new RouteHandler { PolicyBodyOverride = "not-json" };
        using var client = new HttpClient(handler);

        var result = await Transport(client).ListProtectionPoliciesAsync(Config, CancellationToken.None);

        Assert.Equal(DiscoveryStatus.UnexpectedResponse, result.Status);
    }

    [Fact]
    public async Task Discovery_reports_authorization_rejection_separately_from_authentication_failure()
    {
        var handler = new RouteHandler { PolicyStatus = HttpStatusCode.Forbidden };
        using var client = new HttpClient(handler);

        var result = await Transport(client).ListProtectionPoliciesAsync(Config, CancellationToken.None);

        Assert.Equal(DiscoveryStatus.AcronisRejected, result.Status);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("""{"items":{}}""")]
    [InlineData("""{"items":[{"nopolicy":1}]}""")]
    public async Task Discovery_reports_unexpected_response_for_a_valid_json_wrong_shape(string body)
    {
        var handler = new RouteHandler { PolicyBodyOverride = body };
        using var client = new HttpClient(handler);

        var result = await Transport(client).ListProtectionPoliciesAsync(Config, CancellationToken.None);

        Assert.Equal(DiscoveryStatus.UnexpectedResponse, result.Status);
    }

    [Fact]
    public async Task ListResources_never_offers_a_resource_group()
    {
        var handler = new RouteHandler
        {
            ResourceBody = """
            {
              "items": [
                { "id": "77777777-7777-7777-7777-777777777777", "name": "All machines", "is_group": true },
                { "id": "88888888-8888-8888-8888-888888888888", "name": "SERVER-01", "is_group": false }
              ]
            }
            """,
        };
        using var client = new HttpClient(handler);

        var result = await Transport(client).ListResourcesAsync(Config, "11111111-1111-1111-1111-111111111111", CancellationToken.None);

        Assert.Equal(DiscoveryStatus.Succeeded, result.Status);
        Assert.Equal([new AcronisResource("88888888-8888-8888-8888-888888888888", "SERVER-01")], result.Items);
    }

    [Fact]
    public async Task Discovery_follows_the_continuation_cursor_until_the_final_page()
    {
        var handler = new RouteHandler
        {
            PagedPolicyBodies =
            [
                """
                { "items": [ { "policy": [ { "id": "aaaaaaaa-0000-0000-0000-000000000001", "name": "Page one", "type": "policy.protection.total" } ] } ],
                  "paging": { "cursors": { "after": "cursor-1" } } }
                """,
                """
                { "items": [ { "policy": [ { "id": "bbbbbbbb-0000-0000-0000-000000000002", "name": "Page two", "type": "policy.protection.total" } ] } ],
                  "paging": { "cursors": { } } }
                """,
            ],
        };
        using var client = new HttpClient(handler);

        var result = await Transport(client).ListProtectionPoliciesAsync(Config, CancellationToken.None);

        Assert.Equal(DiscoveryStatus.Succeeded, result.Status);
        Assert.Equal(["Page one", "Page two"], result.Items.Select(p => p.Name));
        Assert.Contains("after=cursor-1", handler.Requests[^1].Uri);
    }

    private static HttpAcronisTransport Transport(HttpClient client) =>
        new(client, (_, _) => Task.CompletedTask);

    private sealed record RecordedRequest(string Uri, string? AuthorizationScheme, string? AuthorizationParameter);

    private sealed class RouteHandler : HttpMessageHandler
    {
        private int policyRequests;

        public HttpStatusCode TokenStatus { get; init; } = HttpStatusCode.OK;
        public HttpStatusCode PolicyStatus { get; init; } = HttpStatusCode.OK;
        public string? PolicyBodyOverride { get; init; }
        public string[]? PagedPolicyBodies { get; init; }
        public string ResourceBody { get; init; } = DiscoveryTests.ResourceBody;
        public List<RecordedRequest> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var uri = request.RequestUri!.ToString();
            Requests.Add(new RecordedRequest(uri, request.Headers.Authorization?.Scheme, request.Headers.Authorization?.Parameter));

            if (uri.Contains("/idp/token"))
                return Task.FromResult(new HttpResponseMessage(TokenStatus) { Content = new StringContent(TokenBody) });

            if (uri.Contains("/policy_management/v4/policies"))
            {
                var body = PagedPolicyBodies is { Length: > 0 }
                    ? PagedPolicyBodies[Math.Min(policyRequests++, PagedPolicyBodies.Length - 1)]
                    : PolicyBodyOverride ?? DiscoveryTests.PolicyBody;

                return Task.FromResult(new HttpResponseMessage(PolicyStatus) { Content = new StringContent(body) });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(ResourceBody) });
        }
    }
}
