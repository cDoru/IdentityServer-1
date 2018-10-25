using IdentityServer4.Validation;
using System;
using System.Threading.Tasks;

namespace IdentityServer
{
    public class ExtensionGrantValidator : IExtensionGrantValidator
    {
        public string GrantType { get; } = "custom";

        public Task ValidateAsync(ExtensionGrantValidationContext context)
        {
            throw new NotImplementedException();
        }
    }
}
