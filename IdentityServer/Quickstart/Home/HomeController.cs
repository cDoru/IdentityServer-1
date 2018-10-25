using IdentityServer4.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace IdentityServer4.Quickstart.UI
{
    [SecurityHeaders]
    [AllowAnonymous]
    public class HomeController : Controller
    {
        private readonly IHostingEnvironment _environment;
        private readonly IIdentityServerInteractionService _interactionService;

        public HomeController(IHostingEnvironment environment, IIdentityServerInteractionService interactionService)
        {
            _environment = environment;
            _interactionService = interactionService;
        }

        public async Task<IActionResult> Error(string errorId)
        {
            var vm = new ErrorViewModel();

            var message = await _interactionService.GetErrorContextAsync(errorId);

            if (message == null)
            {
                return View(nameof(Error), vm);
            }

            vm.Error = message;

            if (!_environment.IsDevelopment())
            {
                message.ErrorDescription = null;
            }

            return View(nameof(Error), vm);
        }

        public IActionResult Index()
        {
            return View();
        }
    }
}
