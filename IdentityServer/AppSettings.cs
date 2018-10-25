namespace IdentityServer
{
    public class AppSettings
    {
        public string CertificateThumbprint { get; set; }

        public ConnectionStrings ConnectionStrings { get; set; }
    }

    public class ConnectionStrings
    {
        public string IdentityServer { get; set; }
    }
}
