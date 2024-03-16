using Microsoft.AspNetCore.Mvc;

namespace HDS.AuthorizationServer.Controllers
{
    public class AccountsController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
