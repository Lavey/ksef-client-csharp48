using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using KSeF.Client.Compatibility;
using KSeF.Client.Core.Infrastructure.Rest;
using KSeF.Client.Core.Interfaces.Clients;
using KSeF.Client.Core.Interfaces.Rest;
using KSeF.Client.Core.Models;

namespace KSeF.Client.Clients
{
/// <inheritdoc />
public class RevokePermissionClient : ClientBase, IRevokePermissionClient
{
    public RevokePermissionClient(IRestClient restClient, IRouteBuilder routeBuilder)
        : base(restClient, routeBuilder)
    {
    }
    /// <inheritdoc />
    public Task<OperationResponse> RevokeCommonPermissionAsync(string permissionId, string accessToken, CancellationToken cancellationToken = default)
    {
        Guard.ThrowIfNullOrWhiteSpace(permissionId);
        Guard.ThrowIfNullOrWhiteSpace(accessToken);

        string endpoint = Routes.Permissions.Common.GrantById(Uri.EscapeDataString(permissionId));
        return ExecuteAsync<OperationResponse>(endpoint, HttpMethod.Delete, accessToken, cancellationToken);
    }

    /// <inheritdoc />
    public Task<OperationResponse> RevokeAuthorizationsPermissionAsync(string permissionId, string accessToken, CancellationToken cancellationToken = default)
    {
        Guard.ThrowIfNullOrWhiteSpace(permissionId);
        Guard.ThrowIfNullOrWhiteSpace(accessToken);

        string endpoint = Routes.Permissions.Authorizations.GrantById(Uri.EscapeDataString(permissionId));
        return ExecuteAsync<OperationResponse>(endpoint, HttpMethod.Delete, accessToken, cancellationToken);
    }
}

}
