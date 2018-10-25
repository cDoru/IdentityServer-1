using System.Collections.Generic;

namespace IdentityServer4.Quickstart.UI
{
    public class ConsentViewModel : ConsentInputModel
    {
        public bool AllowRememberConsent { get; set; }

        public string ClientLogoUrl { get; set; }

        public string ClientName { get; set; }

        public string ClientUrl { get; set; }

        public IEnumerable<ScopeViewModel> IdentityScopes { get; set; }

        public IEnumerable<ScopeViewModel> ResourceScopes { get; set; }
    }
}
