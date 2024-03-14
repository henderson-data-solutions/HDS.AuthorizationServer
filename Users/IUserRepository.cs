using Oidc.OpenIddict.AuthorizationServer.Context;
using Oidc.OpenIddict.AuthorizationServer.Models;

namespace Oidc.OpenIddict.AuthorizationServer.Users
{
    public interface IUserRepository
    {
        public Task<IEnumerable<AspNetUsers>> GetUsers();

    }
}
