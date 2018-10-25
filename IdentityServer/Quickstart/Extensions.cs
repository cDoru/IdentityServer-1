using IdentityServer4.Stores;
using System.Threading.Tasks;

namespace IdentityServer4.Quickstart.UI
{
    public static class Extensions
    {
        public static async Task<bool> IsPkceClientAsync(this IClientStore clientStore, string client_id)
        {
            if (string.IsNullOrWhiteSpace(client_id))
            {
                return false;
            }

            var client = await clientStore.FindEnabledClientByIdAsync(client_id);

            return client?.RequirePkce == true;
        }
    }
}
