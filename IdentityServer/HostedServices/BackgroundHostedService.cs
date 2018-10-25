using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityServer
{
    public class BackgroundHostedService : IHostedService, IDisposable
    {
        public BackgroundHostedService(ILogger<BackgroundHostedService> logger)
        {
            Logger = logger;
        }

        private ILogger Logger { get; }

        private Timer Timer { get; set; }

        public void Dispose()
        {
            Timer?.Dispose();
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            Logger.LogInformation(nameof(StartAsync));
            Timer = new Timer(Run, null, TimeSpan.Zero, TimeSpan.FromSeconds(5));

            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            Logger.LogInformation(nameof(StopAsync));
            Timer?.Change(Timeout.Infinite, 0);

            return Task.CompletedTask;
        }

        private void Run(object state)
        {
            Logger.LogInformation(nameof(Run));
        }
    }
}
