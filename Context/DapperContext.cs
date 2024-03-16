using Microsoft.Data.SqlClient;
using System.Data;

namespace HDS.AuthorizationServer.Context
{
    public class DapperContext
    {
        private readonly IConfiguration _config;
        private readonly string _connectionString;
        public DapperContext(IConfiguration config)
        {
            _config = config;
            _connectionString = _config["ConnectionStrings:DefaultConnection"];
        }
        public IDbConnection CreateConnection()
            => new SqlConnection(_connectionString);
    }
}
