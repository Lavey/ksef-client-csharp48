using KSeF.Client.Core.Interfaces.Clients;
using KSeF.Client.Core.Interfaces.Rest;
using KSeF.Client.Core.Models.Certificates;
using KSeF.Client.Http;

using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using System.Threading;
namespace KSeF.Client.Clients
{
/// <inheritdoc />
public class CryptographyClient : ICryptographyClient
{
    private readonly IRestClient _restClient;

    public CryptographyClient(IRestClient restClient)
    {
        _restClient = restClient;
    }

    /// <inheritdoc />
    public async Task<ICollection<PemCertificateInfo>> GetPublicCertificatesAsync(CancellationToken cancellationToken = default)
    {
        return await _restClient.SendAsync<ICollection<PemCertificateInfo>, string>(HttpMethod.Get,
                                                                      "/v2/security/public-key-certificates",
                                                                      default,
                                                                      default,
                                                                      RestClient.DefaultContentType,
                                                                      cancellationToken).ConfigureAwait(false);
    }
}


}
