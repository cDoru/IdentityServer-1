using IdentityModel;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System.IO;

namespace IdentityServer.Client
{
    public class Startup
    {
        public Startup(IHostingEnvironment environment)
        {
            Configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile($"{nameof(AppSettings)}.json")
                .AddJsonFile($"{nameof(AppSettings)}.{environment.EnvironmentName}.json", true)
                .AddEnvironmentVariables()
                .Build();

            Environment = environment;
        }

        private IConfiguration Configuration { get; }

        private IHostingEnvironment Environment { get; }

        public void Configure(IApplicationBuilder application)
        {
            application.UseDeveloperExceptionPage();
            application.UseAuthentication();
            application.UseStaticFiles();
            application.UseMvcWithDefaultRoute();
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<AppSettings>(Configuration);
            services.AddSingleton(resolver => resolver.GetRequiredService<IOptions<AppSettings>>().Value);
            var appSettings = services.BuildServiceProvider().GetService<AppSettings>();

            services.AddMvc();

            services
                .AddAuthentication(options =>
                {
                    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                })
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
                {
                    options.Authority = appSettings.Authority;
                    options.ClientId = appSettings.ClientId;
                    options.ClientSecret = appSettings.ClientSecret;
                    options.Scope.Clear();
                    options.Scope.Add("openid");
                    options.Scope.Add(appSettings.Scope);
                    options.SaveTokens = true;
                    options.RequireHttpsMetadata = !Environment.IsDevelopment();
                    options.ResponseType = OidcConstants.ResponseTypes.IdTokenToken;
                    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                });
        }
    }
}
