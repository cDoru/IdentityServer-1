using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Net.Http;
using System.Threading.Tasks;

namespace IdentityServer.Client.Controllers
{
    public class HomeController : Controller
    {
        public HomeController(IOptions<AppSettings> appSettings)
        {
            AppSettings = appSettings.Value;
        }

        private AppSettings AppSettings { get; }

        public async Task<IActionResult> Api()
        {
            var tokenResponse = await RequestTokenForClientCredentialsAsync().ConfigureAwait(false);

            var apiResponse = await GetApi(tokenResponse.AccessToken).ConfigureAwait(false);

            var model = new ViewModel
            {
                Token = tokenResponse.AccessToken,
                ApiResponse = apiResponse
            };

            return View(model);
        }

        [Authorize]
        public IActionResult Implicit()
        {
            return View();
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Logout()
        {
            return SignOutResult();
        }

        public async Task<IActionResult> ResourceOwnerPassword()
        {
            var tokenResponse = await RequestTokenForResourceOwnerPasswordAsync().ConfigureAwait(false);

            var apiResponse = await GetApi(tokenResponse.AccessToken).ConfigureAwait(false);

            var model = new ViewModel
            {
                Token = tokenResponse.AccessToken,
                ApiResponse = apiResponse
            };

            return View(model);
        }

        private static SignOutResult SignOutResult()
        {
            return new SignOutResult(new[]
            {
                CookieAuthenticationDefaults.AuthenticationScheme,
                OpenIdConnectDefaults.AuthenticationScheme
            });
        }

        private async Task<TokenClient> CreateTokenClient()
        {
            var discoveryClient = await DiscoveryClient.GetAsync(AppSettings.Authority).ConfigureAwait(false);

            return new TokenClient(discoveryClient.TokenEndpoint, AppSettings.ClientId, AppSettings.ClientSecret);
        }

        private Task<string> GetApi(string token)
        {
            var httpClient = new HttpClient();

            httpClient.SetBearerToken(token);

            return httpClient.GetStringAsync(AppSettings.ApiUrl);
        }

        private async Task<TokenResponse> RequestTokenForClientCredentialsAsync()
        {
            var tokenClient = await CreateTokenClient().ConfigureAwait(false);

            return await tokenClient.RequestClientCredentialsAsync(AppSettings.Scope).ConfigureAwait(false);
        }

        private async Task<TokenResponse> RequestTokenForResourceOwnerPasswordAsync()
        {
            var tokenClient = await CreateTokenClient().ConfigureAwait(false);

            return await tokenClient.RequestResourceOwnerPasswordAsync(AppSettings.UserUsername, AppSettings.UserPassword).ConfigureAwait(false);
        }
    }
}
