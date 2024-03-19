using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using System.Data;
using HDS.AuthorizationServer.Context;
using HDS.AuthorizationServer.Models;
using HDS.AuthorizationServer.Users;
using HDS.AuthorizationServer.Classes;
using Dapper;

namespace HDS.AuthorizationServer.Repository
{
    public class UserRepository : IUserRepository
    {

        public UserRepository() 
        {

        }

        public async Task<AspNetUser> GetUserByEmail(string email)
        {
            List<AspNetUser> users = new List<AspNetUser>();

            var p = new DynamicParameters();
            p.Add("@EmailAddress", email);

            DataToolsReturnObject<AspNetUser> obj = await DataTools.ExecuteStoredProcedure<AspNetUser>("GetUserDataByEmail", p);

            if(obj.error == string.Empty)
            {
                users = obj.results;
                return users.First<AspNetUser>();
            }

            return null;
        }

        public async Task<List<CustomClaim>> GetClaimsByEmail(string email)
        {
            List<CustomClaim> claims = new List<CustomClaim>();
            var p = new DynamicParameters();
            p.Add("@EmailAddress", email);

            DataToolsReturnObject<CustomClaim> obj = await DataTools.ExecuteStoredProcedure<CustomClaim>("GetClaimsByEmail", p);

            if(obj.error == string.Empty)
            {
                claims = obj.results;
                return claims;
            }

            return null;
        }
    }
}
