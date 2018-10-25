using IdentityModel;
using IdentityServer;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer4.Quickstart.UI
{
    [SecurityHeaders]
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly IClientStore _clientStore;
        private readonly IEventService _eventService;
        private readonly IIdentityServerInteractionService _interactionService;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public AccountController(
            IClientStore clientStore,
            IEventService eventService,
            IIdentityServerInteractionService interactionService,
            IAuthenticationSchemeProvider schemeProvider,
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager)
        {
            _clientStore = clientStore;
            _eventService = eventService;
            _interactionService = interactionService;
            _schemeProvider = schemeProvider;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            var vm = await BuildLoginViewModelAsync(returnUrl).ConfigureAwait(false);

            if (vm.IsExternalLoginOnly)
            {
                return RedirectToAction("Challenge", "External", new { provider = vm.ExternalLoginScheme, returnUrl });
            }

            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            var context = await _interactionService.GetAuthorizationContextAsync(model.ReturnUrl).ConfigureAwait(false);

            if (button != "login")
            {
                if (context == null)
                {
                    return Redirect("~/");
                }

                await _interactionService.GrantConsentAsync(context, ConsentResponse.Denied).ConfigureAwait(false);

                if (await _clientStore.IsPkceClientAsync(context.ClientId).ConfigureAwait(false))
                {
                    return View("Redirect", new RedirectViewModel { RedirectUrl = model.ReturnUrl });
                }

                return Redirect(model.ReturnUrl);
            }

            if (ModelState.IsValid)
            {
                var signedIn = _signInManager.PasswordSignInAsync(model.Username, model.Password, true, true).Result;

                if (signedIn != null)
                {
                    var user = _userManager.FindByNameAsync(model.Username).Result;

                    await _eventService.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id.ToString(), user.UserName)).ConfigureAwait(false);

                    AuthenticationProperties props = null;

                    if (AccountOptions.AllowRememberLogin && model.RememberLogin)
                    {
                        props = new AuthenticationProperties
                        {
                            IsPersistent = true,
                            ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration)
                        };
                    }

                    await HttpContext.SignInAsync(user.Id.ToString(), user.UserName, props).ConfigureAwait(false);

                    if (context != null)
                    {
                        if (await _clientStore.IsPkceClientAsync(context.ClientId).ConfigureAwait(false))
                        {
                            return View("Redirect", new RedirectViewModel { RedirectUrl = model.ReturnUrl });
                        }

                        return Redirect(model.ReturnUrl);
                    }

                    if (Url.IsLocalUrl(model.ReturnUrl))
                    {
                        return Redirect(model.ReturnUrl);
                    }

                    if (string.IsNullOrEmpty(model.ReturnUrl))
                    {
                        return Redirect("~/");
                    }

                    throw new Exception("invalid return URL");
                }

                await _eventService.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials")).ConfigureAwait(false);

                ModelState.AddModelError("", AccountOptions.InvalidCredentialsErrorMessage);
            }

            var vm = await BuildLoginViewModelAsync(model).ConfigureAwait(false);

            return View(vm);
        }

        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            var vm = await BuildLogoutViewModelAsync(logoutId).ConfigureAwait(false);

            if (!vm.ShowLogoutPrompt)
            {
                return await Logout(vm).ConfigureAwait(false);
            }

            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId).ConfigureAwait(false);

            if (User?.Identity.IsAuthenticated == true)
            {
                await HttpContext.SignOutAsync().ConfigureAwait(false);

                await _eventService.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName())).ConfigureAwait(false);
            }

            if (!vm.TriggerExternalSignout)
            {
                return View("LoggedOut", vm);
            }

            var url = Url.Action(nameof(Logout), new { logoutId = vm.LogoutId });

            return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            var logout = await _interactionService.GetLogoutContextAsync(logoutId).ConfigureAwait(false);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated != true)
            {
                return vm;
            }

            var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;

            if (idp == null || idp == IdentityServerConstants.LocalIdentityProvider)
            {
                return vm;
            }

            var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp).ConfigureAwait(false);

            if (!providerSupportsSignout)
            {
                return vm;
            }

            if (vm.LogoutId == null)
            {
                vm.LogoutId = await _interactionService.CreateLogoutContextAsync().ConfigureAwait(false);
            }

            vm.ExternalAuthenticationScheme = idp;

            return vm;
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interactionService.GetAuthorizationContextAsync(returnUrl).ConfigureAwait(false);

            if (context?.IdP != null)
            {
                return new LoginViewModel
                {
                    EnableLocalLogin = false,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                    ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } }
                };
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync().ConfigureAwait(false);

            var providers = schemes
                .Where(x => x.DisplayName != null || (x.Name.Equals(AccountOptions.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase)))
                .Select(x => new ExternalProvider { DisplayName = x.DisplayName, AuthenticationScheme = x.Name })
                .ToList();

            var allowLocal = true;

            if (context?.ClientId == null)
            {
                return new LoginViewModel
                {
                    AllowRememberLogin = AccountOptions.AllowRememberLogin,
                    EnableLocalLogin = AccountOptions.AllowLocalLogin,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                    ExternalProviders = providers.ToArray()
                };
            }

            var client = await _clientStore.FindEnabledClientByIdAsync(context.ClientId).ConfigureAwait(false);

            if (client == null)
            {
                return new LoginViewModel
                {
                    AllowRememberLogin = AccountOptions.AllowRememberLogin,
                    EnableLocalLogin = AccountOptions.AllowLocalLogin,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                    ExternalProviders = providers.ToArray()
                };
            }

            allowLocal = client.EnableLocalLogin;

            if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
            {
                providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl).ConfigureAwait(false);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;

            return vm;
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interactionService.GetLogoutContextAsync(logoutId).ConfigureAwait(false);

            if (context?.ShowSignoutPrompt != false)
            {
                return vm;
            }

            vm.ShowLogoutPrompt = false;

            return vm;
        }
    }
}
