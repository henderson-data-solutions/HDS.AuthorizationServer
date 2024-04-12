using HDS.AuthorizationServer.Context;
using HDS.AuthorizationServer.Models;

namespace HDS.AuthorizationServer.Interfaces
{
    public interface IAuthorizationRepository
    {
        public Task<AspNetUser> GetUserByEmail(string email);

    }
}
