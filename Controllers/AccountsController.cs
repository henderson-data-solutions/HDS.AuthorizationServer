using Microsoft.AspNetCore.Mvc;

namespace Oidc.OpenIddict.AuthorizationServer.Controllers
{
    public class AccountsController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
