using KSeF.Client.Core.Interfaces.Services;
using Microsoft.Extensions.Hosting;

using System.Threading.Tasks;
using System.Threading;
using System;
namespace KSeF.Client.Api.Services
{
public sealed partial class CryptographyWarmupHostedService : IHostedService
{
    private readonly ICryptographyService cryptographyService;
    private readonly CryptographyServiceWarmupMode warmupMode;

    public CryptographyWarmupHostedService(
        ICryptographyService cryptographyService,
        CryptographyServiceWarmupMode warmupMode = CryptographyServiceWarmupMode.Blocking)
    {
        this.cryptographyService = cryptographyService;
        this.warmupMode = warmupMode;
    }
    public Task StartAsync(CancellationToken cancellationToken)
    {
        switch (warmupMode)
        {
            case CryptographyServiceWarmupMode.Disabled:
                return Task.CompletedTask;
            case CryptographyServiceWarmupMode.NonBlocking:
                _ = Task.Run(() => SafeWarmup(cancellationToken), CancellationToken.None);
                return Task.CompletedTask;
            case CryptographyServiceWarmupMode.Blocking:
                return SafeWarmup(cancellationToken);
            default:
                return Task.CompletedTask;
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private async Task SafeWarmup(CancellationToken cancellationToken)
    {
        try
        {
            await cryptographyService.WarmupAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            if (warmupMode == CryptographyServiceWarmupMode.Blocking)
            {
                throw;
            }
        }
    }
}

}
