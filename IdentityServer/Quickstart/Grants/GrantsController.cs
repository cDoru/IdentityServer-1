using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer4.Quickstart.UI
{
    [SecurityHeaders]
    [Authorize]
    public class GrantsController : Controller
    {
        private readonly IClientStore _clientStore;
        private readonly IEventService _eventService;
        private readonly IIdentityServerInteractionService _interactionService;
        private readonly IResourceStore _resourceStore;

        public GrantsController(
            IClientStore clientStore,
            IEventService eventService,
            IIdentityServerInteractionService interactionService,
            IResourceStore resourceStore)
        {
            _clientStore = clientStore;
            _eventService = eventService;
            _interactionService = interactionService;
            _resourceStore = resourceStore;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            return View(nameof(Index), await BuildViewModelAsync());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Revoke(string clientId)
        {
            await _interactionService.RevokeUserConsentAsync(clientId);
            await _eventService.RaiseAsync(new GrantsRevokedEvent(User.GetSubjectId(), clientId));

            return RedirectToAction(nameof(Index));
        }

        private async Task<GrantsViewModel> BuildViewModelAsync()
        {
            var grants = await _interactionService.GetAllUserConsentsAsync();

            var list = new List<GrantViewModel>();

            foreach (var grant in grants)
            {
                var client = await _clientStore.FindClientByIdAsync(grant.ClientId);

                if (client == null)
                {
                    continue;
                }

                var resources = await _resourceStore.FindResourcesByScopeAsync(grant.Scopes);

                var item = new GrantViewModel
                {
                    ClientId = client.ClientId,
                    ClientName = client.ClientName ?? client.ClientId,
                    ClientLogoUrl = client.LogoUri,
                    ClientUrl = client.ClientUri,
                    Created = grant.CreationTime,
                    Expires = grant.Expiration,
                    IdentityGrantNames = resources.IdentityResources.Select(x => x.DisplayName ?? x.Name).ToArray(),
                    ApiGrantNames = resources.ApiResources.Select(x => x.DisplayName ?? x.Name).ToArray()
                };

                list.Add(item);
            }

            return new GrantsViewModel
            {
                Grants = list
            };
        }
    }
}
