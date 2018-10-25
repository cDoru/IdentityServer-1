using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.Api
{
    [ApiController]
    [Authorize]
    [Route("[controller]")]
    public class ApiController : ControllerBase
    {
        [HttpGet]
        public ActionResult<string> Get()
        {
            return "Success";
        }
    }
}
