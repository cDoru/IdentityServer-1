using IdentityServer4;
using IdentityServer4.Models;
using System.Collections.Generic;

namespace IdentityServer
{
    public static class Seed
    {
        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new[]
            {
                new ApiResource
                {
                    Name = "api",
                    Description = "API",
                    DisplayName = "API",
                    Scopes = { new Scope("api") },
                    ApiSecrets = { new Secret("secret".Sha512()) }
                }
            };
        }

        public static IEnumerable<Client> GetClients()
        {
            return new[]
            {
                new Client
                {
                    ClientId = "client",
                    ClientName = "Client",
                    ClientSecrets = { new Secret("secret".Sha512()) },
                    AllowedScopes = { IdentityServerConstants.StandardScopes.OpenId, "api" },
                    RequireConsent = false,
                    AllowAccessTokensViaBrowser = true,
                    AllowOfflineAccess = true,
                    AlwaysSendClientClaims = true,
                    AccessTokenType = AccessTokenType.Jwt,
                    AllowedGrantTypes = GrantTypes.ResourceOwnerPasswordAndClientCredentials
                }
            };
        }

        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new[]
            {
                new IdentityResources.OpenId()
            };
        }

        public static IEnumerable<ApplicationUser> GetUsers()
        {
            return new[]
            {
                new ApplicationUser { UserName = "admin" }
            };
        }
    }
}
