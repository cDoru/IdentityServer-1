namespace IdentityServer4.Quickstart.UI
{
    public class ProcessConsentResult
    {
        public string ClientId { get; set; }

        public bool HasValidationError => ValidationError != null;

        public bool IsRedirect => RedirectUri != null;

        public string RedirectUri { get; set; }

        public bool ShowView => ViewModel != null;

        public string ValidationError { get; set; }

        public ConsentViewModel ViewModel { get; set; }
    }
}
