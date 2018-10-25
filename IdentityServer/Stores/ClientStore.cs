using IdentityServer4.Models;
using IdentityServer4.Stores;
using System.Threading.Tasks;

namespace IdentityServer
{
    public class ClientStore : IClientStore
    {
        public ClientStore(IRepository repository)
        {
            Repository = repository;
        }

        private IRepository Repository { get; }

        public Task<Client> FindClientByIdAsync(string clientId)
        {
            return Repository.SingleOrDefaultAsync<Client>(x => x.ClientId == clientId);
        }
    }
}
