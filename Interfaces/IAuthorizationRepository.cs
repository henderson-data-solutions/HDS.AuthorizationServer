using HDS.AuthorizationServer.Context;
using HDS.AuthorizationServer.Models;

namespace HDS.AuthorizationServer.Interfaces
{
    public interface IAuthorizationRepository
    {
        public Task<AspNetUser> GetUserByEmail(string email);
        public Task<TwoFactorResults> Generate2FA(int userid);
        Task<List<CustomClaim>> GetClaimsByEmail(string email);
        public Task<AspNetUser> Check2FA(string code, Guid lookup);
    }
}
