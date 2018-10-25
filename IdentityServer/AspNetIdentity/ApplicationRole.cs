using AspNetCore.Identity.MongoDbCore.Models;
using MongoDbGenericRepository.Attributes;
using System;

namespace IdentityServer
{
    [CollectionName("Role")]
    public class ApplicationRole : MongoIdentityRole<Guid>
    {
        public ApplicationRole() { }

        public ApplicationRole(string roleName) : base(roleName) { }
    }
}
