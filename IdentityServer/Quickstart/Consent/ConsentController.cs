using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer4.Quickstart.UI
{
    [SecurityHeaders]
    [Authorize]
    public class ConsentController : Controller
    {
        private readonly IClientStore _clientStore;
        private readonly IEventService _eventService;
        private readonly IIdentityServerInteractionService _interactionService;
        private readonly ILogger<ConsentController> _logger;
        private readonly IResourceStore _resourceStore;

        public ConsentController(
            IClientStore clientStore,
            IEventService eventService,
            IIdentityServerInteractionService interactionService,
            ILogger<ConsentController> logger,
            IResourceStore resourceStore)
        {
            _clientStore = clientStore;
            _eventService = eventService;
            _interactionService = interactionService;
            _logger = logger;
            _resourceStore = resourceStore;
        }

        public ScopeViewModel CreateScopeViewModel(Scope scope, bool check)
        {
            return new ScopeViewModel
            {
                Name = scope.Name,
                DisplayName = scope.DisplayName,
                Description = scope.Description,
                Emphasize = scope.Emphasize,
                Required = scope.Required,
                Checked = check || scope.Required
            };
        }

        [HttpGet]
        public async Task<IActionResult> Index(string returnUrl)
        {
            var vm = await BuildViewModelAsync(returnUrl);

            return vm != null ? View(nameof(Index), vm) : View("Error");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Index(ConsentInputModel model)
        {
            var result = await ProcessConsent(model);

            if (result.IsRedirect)
            {
                if (await _clientStore.IsPkceClientAsync(result.ClientId))
                {
                    return View(nameof(Redirect), new RedirectViewModel { RedirectUrl = result.RedirectUri });
                }

                return Redirect(result.RedirectUri);
            }

            if (result.HasValidationError)
            {
                ModelState.AddModelError("", result.ValidationError);
            }

            return result.ShowView ? View(nameof(Index), result.ViewModel) : View("Error");
        }

        private async Task<ConsentViewModel> BuildViewModelAsync(string returnUrl, ConsentInputModel model = null)
        {
            var request = await _interactionService.GetAuthorizationContextAsync(returnUrl);

            if (request != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(request.ClientId);

                if (client != null)
                {
                    var resources = await _resourceStore.FindEnabledResourcesByScopeAsync(request.ScopesRequested);

                    if (resources != null && (resources.IdentityResources.Any() || resources.ApiResources.Any()))
                    {
                        return CreateConsentViewModel(model, returnUrl, request, client, resources);
                    }

                    _logger.LogError("No scopes matching: {0}", request.ScopesRequested.Aggregate((x, y) => x + ", " + y));
                }
                else
                {
                    _logger.LogError("Invalid client id: {0}", request.ClientId);
                }
            }
            else
            {
                _logger.LogError("No consent request matching request: {0}", returnUrl);
            }

            return null;
        }

        private ConsentViewModel CreateConsentViewModel(
            ConsentInputModel model,
            string returnUrl,
            AuthorizationRequest request,
            Client client,
            Resources resources)
        {
            var vm = new ConsentViewModel
            {
                AllowRememberConsent = client.AllowRememberConsent,
                ClientLogoUrl = client.LogoUri,
                ClientName = client.ClientName ?? client.ClientId,
                ClientUrl = client.ClientUri,
                RememberConsent = model?.RememberConsent ?? true,
                ReturnUrl = returnUrl,
                ScopesConsented = model?.ScopesConsented ?? Enumerable.Empty<string>()
            };

            vm.IdentityScopes = resources.IdentityResources.Select(x => CreateScopeViewModel(x, vm.ScopesConsented.Contains(x.Name) || model == null)).ToArray();
            vm.ResourceScopes = resources.ApiResources.SelectMany(x => x.Scopes).Select(x => CreateScopeViewModel(x, vm.ScopesConsented.Contains(x.Name) || model == null)).ToArray();

            if (ConsentOptions.EnableOfflineAccess && resources.OfflineAccess)
            {
                vm.ResourceScopes = vm.ResourceScopes.Union(new[] {
                    GetOfflineAccessScope(vm.ScopesConsented.Contains(IdentityServerConstants.StandardScopes.OfflineAccess) || model == null)
                });
            }

            return vm;
        }

        private ScopeViewModel CreateScopeViewModel(IdentityResource identity, bool check)
        {
            return new ScopeViewModel
            {
                Name = identity.Name,
                DisplayName = identity.DisplayName,
                Description = identity.Description,
                Emphasize = identity.Emphasize,
                Required = identity.Required,
                Checked = check || identity.Required
            };
        }

        private ScopeViewModel GetOfflineAccessScope(bool check)
        {
            return new ScopeViewModel
            {
                Name = IdentityServerConstants.StandardScopes.OfflineAccess,
                DisplayName = ConsentOptions.OfflineAccessDisplayName,
                Description = ConsentOptions.OfflineAccessDescription,
                Emphasize = true,
                Checked = check
            };
        }

        private async Task<ProcessConsentResult> ProcessConsent(ConsentInputModel model)
        {
            var result = new ProcessConsentResult();

            var request = await _interactionService.GetAuthorizationContextAsync(model.ReturnUrl);

            if (request == null)
            {
                return result;
            }

            ConsentResponse grantedConsent = null;

            switch (model.Button)
            {
                case "no":
                {
                    grantedConsent = ConsentResponse.Denied;
                    await _eventService.RaiseAsync(new ConsentDeniedEvent(User.GetSubjectId(), result.ClientId, request.ScopesRequested));
                    break;
                }
                case "yes":
                {
                    if (model.ScopesConsented != null && model.ScopesConsented.Any())
                    {
                        var scopes = model.ScopesConsented;

                        if (ConsentOptions.EnableOfflineAccess == false)
                        {
                            scopes = scopes.Where(x => x != IdentityServerConstants.StandardScopes.OfflineAccess);
                        }

                        grantedConsent = new ConsentResponse
                        {
                            RememberConsent = model.RememberConsent,
                            ScopesConsented = scopes.ToArray()
                        };

                        await _eventService.RaiseAsync(new ConsentGrantedEvent(User.GetSubjectId(), request.ClientId,
                            request.ScopesRequested, grantedConsent.ScopesConsented, grantedConsent.RememberConsent));
                    }
                    else
                    {
                        result.ValidationError = ConsentOptions.MustChooseOneErrorMessage;
                    }

                    break;
                }
                default:
                {
                    result.ValidationError = ConsentOptions.InvalidSelectionErrorMessage;
                    break;
                }
            }

            if (grantedConsent != null)
            {
                await _interactionService.GrantConsentAsync(request, grantedConsent);
                result.RedirectUri = model.ReturnUrl;
                result.ClientId = request.ClientId;
            }
            else
            {
                result.ViewModel = await BuildViewModelAsync(model.ReturnUrl, model);
            }

            return result;
        }
    }
}
