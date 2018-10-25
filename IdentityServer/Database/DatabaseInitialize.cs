using IdentityServer4.Models;
using Microsoft.AspNetCore.Identity;
using MongoDB.Bson.Serialization.Conventions;
using System.Linq;

namespace IdentityServer
{
    public class DatabaseInitialize : IDatabaseInitialize
    {
        public DatabaseInitialize(IRepository repository, UserManager<ApplicationUser> userManager)
        {
            Repository = repository;
            UserManager = userManager;
        }

        private IRepository Repository { get; }

        private UserManager<ApplicationUser> UserManager { get; }

        public void Initialize()
        {
            var conventionPack = new ConventionPack { new IgnoreExtraElementsConvention(true) };

            ConventionRegistry.Register(nameof(IgnoreExtraElementsConvention), conventionPack, _ => true);

            if (!Repository.Any<ApiResource>())
            {
                Seed.GetApiResources().ToList().ForEach(apiResource => Repository.Add(apiResource));
            }

            if (!Repository.Any<Client>())
            {
                Seed.GetClients().ToList().ForEach(client => Repository.Add(client));
            }

            if (!Repository.Any<IdentityResource>())
            {
                Seed.GetIdentityResources().ToList().ForEach(identityResource => Repository.Add(identityResource));
            }

            if (!Repository.Any<ApplicationUser>())
            {
                foreach (var user in Seed.GetUsers().ToList())
                {
                    var result = UserManager.CreateAsync(user, "P@$$word123456").Result;
                }
            }
        }
    }
}
