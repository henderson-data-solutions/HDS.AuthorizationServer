using HDS.AuthorizationServer.Context;
using HDS.AuthorizationServer.Models;

namespace HDS.AuthorizationServer.Users
{
    public interface IUserRepository
    {
        public Task<IEnumerable<AspNetUsers>> GetUsers();

    }
}
