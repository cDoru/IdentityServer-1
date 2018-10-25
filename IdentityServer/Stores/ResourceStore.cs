using IdentityServer4.Models;
using IdentityServer4.Stores;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer
{
    public class ResourceStore : IResourceStore
    {
        public ResourceStore(IRepository repository)
        {
            Repository = repository;
        }

        private IRepository Repository { get; }

        public Task<ApiResource> FindApiResourceAsync(string name)
        {
            return Repository.SingleOrDefaultAsync<ApiResource>(x => x.Name == name);
        }

        public Task<IEnumerable<ApiResource>> FindApiResourcesByScopeAsync(IEnumerable<string> scopeNames)
        {
            return Repository.ListAsync<ApiResource>(x => scopeNames.Contains(x.Name));
        }

        public Task<IEnumerable<IdentityResource>> FindIdentityResourcesByScopeAsync(IEnumerable<string> scopeNames)
        {
            return Repository.ListAsync<IdentityResource>(x => scopeNames.Contains(x.Name));
        }

        public Task<Resources> GetAllResourcesAsync()
        {
            var identityResources = Repository.List<IdentityResource>().ToList();

            var apiResources = Repository.List<ApiResource>().ToList();

            var resources = new Resources(identityResources, apiResources);

            return Task.FromResult(resources);
        }
    }
}
