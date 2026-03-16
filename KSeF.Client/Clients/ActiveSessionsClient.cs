using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using System.Threading;
using KSeF.Client.Compatibility;
﻿using KSeF.Client.Core.Infrastructure.Rest;
using KSeF.Client.Core.Interfaces.Clients;
using KSeF.Client.Core.Interfaces.Rest;
using KSeF.Client.Core.Models.Sessions.ActiveSessions;
using System.Text;
using System.Text.RegularExpressions;
using KSeF.Client.Http.Helpers;

namespace KSeF.Client.Clients
{
/// <inheritdoc />
public class ActiveSessionsClient : ClientBase, IActiveSessionsClient
{
    public ActiveSessionsClient(IRestClient restClient, IRouteBuilder routeBuilder)
        : base(restClient, routeBuilder)
    {
    }

    /// <inheritdoc />
    public Task<AuthenticationListResponse> GetActiveSessions(string accessToken, int? pageSize, string continuationToken, CancellationToken cancellationToken = default)
    {
        Guard.ThrowIfNullOrWhiteSpace(accessToken);

        StringBuilder urlBuilder = new StringBuilder(Routes.ActiveSessions.Session);

        PaginationHelper.AppendPagination(null, pageSize, urlBuilder);

        string url = urlBuilder.ToString();
        return ExecuteAsync<AuthenticationListResponse>(url, HttpMethod.Get, accessToken,
                                                                          !string.IsNullOrEmpty(continuationToken) ?
                                                                               new Dictionary<string, string> { { "x-continuation-token", Regex.Unescape(continuationToken) } }
                                                                               : null,
                                                                          cancellationToken);
    }

    /// <inheritdoc />
    public Task RevokeCurrentSessionAsync(string token, CancellationToken cancellationToken = default)
    {
        Guard.ThrowIfNullOrWhiteSpace(token);

        return ExecuteAsync(Routes.ActiveSessions.CurrentSession, HttpMethod.Delete, token, cancellationToken);
    }

    /// <inheritdoc />
    public Task RevokeSessionAsync(string sessionReferenceNumber, string accessToken, CancellationToken cancellationToken = default)
    {
        Guard.ThrowIfNullOrWhiteSpace(sessionReferenceNumber);
        Guard.ThrowIfNullOrWhiteSpace(accessToken);

        string endpoint = $"{Routes.ActiveSessions.Session}/{Uri.EscapeDataString(sessionReferenceNumber)}";
        return ExecuteAsync(endpoint, HttpMethod.Delete, accessToken, cancellationToken);
    }
}

}
