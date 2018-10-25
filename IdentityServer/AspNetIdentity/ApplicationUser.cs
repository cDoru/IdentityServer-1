using AspNetCore.Identity.MongoDbCore.Models;
using MongoDbGenericRepository.Attributes;
using System;

namespace IdentityServer
{
    [CollectionName("User")]
    public class ApplicationUser : MongoIdentityUser<Guid>
    {
        public ApplicationUser() { }

        public ApplicationUser(string userName, string email) : base(userName, email) { }
    }
}
