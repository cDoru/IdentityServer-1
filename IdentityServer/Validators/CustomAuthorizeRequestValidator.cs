using IdentityServer4.Validation;
using System;
using System.Threading.Tasks;

namespace IdentityServer
{
    public class CustomAuthorizeRequestValidator : ICustomAuthorizeRequestValidator
    {
        public Task ValidateAsync(CustomAuthorizeRequestValidationContext context)
        {
            throw new NotImplementedException();
        }
    }
}
