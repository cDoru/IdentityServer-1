using IdentityServer4.Services;
using System;
using System.Threading.Tasks;

namespace IdentityServer
{
    public class CorsPoliceService : ICorsPolicyService
    {
        public Task<bool> IsOriginAllowedAsync(string origin)
        {
            throw new NotImplementedException();
        }
    }
}
