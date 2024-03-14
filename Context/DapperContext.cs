using Microsoft.Data.SqlClient;
using System.Data;

namespace Oidc.OpenIddict.AuthorizationServer.Context
{
    public class DapperContext
    {
        private readonly IConfiguration _configuration;
        private readonly string _connectionString;
        public DapperContext(IConfiguration configuration)
        {
            _configuration = configuration;
            _connectionString = "Server=L3\\SQLDEV;Database=OpenIDDictDB;TrustServerCertificate=True;Trusted_Connection=True;MultipleActiveResultSets=true";
        }
        public IDbConnection CreateConnection()
            => new SqlConnection(_connectionString);
    }
}
