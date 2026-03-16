using KSeF.Client.Core.Interfaces.Clients;
using KSeF.Client.Core.Interfaces.Services;
using KSeF.Client.Core.Models.Certificates;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Threading;
using System;
namespace KSeF.Client.Api.Services.Internal
{
/// <summary>
/// Domyślna implementacja interfejsu ICertificateFetcher, która pobiera
/// certyfikaty KSeF przy użyciu ICryptographyClient.
/// </summary>
/// <remarks>
/// Inicjalizuje nową instancję klasy DefaultCertificateFetcher.
/// </remarks>
/// <param name="cryptographyClient">Klient kryptograficzny, z którego będą pobierane certyfikaty.
/// Zostanie on wstrzyknięty przez kontener DI.</param>
public class DefaultCertificateFetcher : ICertificateFetcher
{
    private readonly ICryptographyClient _cryptographyClient;

    public DefaultCertificateFetcher(ICryptographyClient cryptographyClient)
    {
        _cryptographyClient = cryptographyClient ?? throw new ArgumentNullException(nameof(cryptographyClient));
    }

    /// <inheritdoc />
    public Task<ICollection<PemCertificateInfo>> GetCertificatesAsync(CancellationToken cancellationToken)
    {
        return _cryptographyClient.GetPublicCertificatesAsync(cancellationToken);
    }
}
}
