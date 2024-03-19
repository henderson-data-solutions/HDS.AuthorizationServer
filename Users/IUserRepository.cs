using HDS.AuthorizationServer.Context;
using HDS.AuthorizationServer.Models;

namespace HDS.AuthorizationServer.Users
{
    public interface IUserRepository
    {
        public Task<AspNetUser> GetUserByEmail(string email);

    }
}
