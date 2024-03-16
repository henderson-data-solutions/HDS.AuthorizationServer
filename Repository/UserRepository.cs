using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using System.Data;
using HDS.AuthorizationServer.Context;
using HDS.AuthorizationServer.Models;
using HDS.AuthorizationServer.Users;
using Dapper;
    
namespace HDS.AuthorizationServer.Repository
{
    public class UserRepository : IUserRepository
    {

        private readonly DapperContext _context;

        public UserRepository(DapperContext context) 
        {
            _context = context;
        }

        public async Task<IEnumerable<AspNetUsers>> GetUsers()
        {
            var query = "SELECT * FROM AspNetUsers";
            using (var connection = _context.CreateConnection())
            {
                var users = await connection.QueryAsync<AspNetUsers>(query);
                return users.ToList();
            }
        }


    }
}
