using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using System.Data;
using HDS.AuthorizationServer.Context;
using HDS.AuthorizationServer.Models;
using HDS.AuthorizationServer.Interfaces;
using HDS.AuthorizationServer.Classes;
using Dapper;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages.Manage;

namespace HDS.AuthorizationServer.Repository
{
    public class AuthorizationRepository : IAuthorizationRepository
    {
        private readonly ILogger _logger;

        public AuthorizationRepository(ILogger<AuthorizationRepository> logger) 
        {
            _logger = logger;
        }

        public async Task<TwoFactorResults> Generate2FA(int userid)
        {
            var p = new DynamicParameters();
            p.Add("@UserID", userid);
            
            DataToolsReturnObject<TwoFactorResults> obj = await DataTools.ExecuteStoredProcedure<TwoFactorResults>("Generate2FA", p);

            TwoFactorResults rtnValue = obj.results.First<TwoFactorResults>();

            return rtnValue;
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
