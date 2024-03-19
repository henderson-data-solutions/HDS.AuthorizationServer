using NLog.LayoutRenderers.Wrappers;
using Dapper;
using HDS.AuthorizationServer.Context;
using HDS.AuthorizationServer.Models;
using System.Configuration;
using Microsoft.AspNetCore.Http.HttpResults;

namespace HDS.AuthorizationServer.Classes
{
    public static class DataTools
    {
        private static IConfiguration _config { get; }

        static DataTools() 
        { 
            var builder = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);

            _config = builder.Build();
        }

        public async static Task<DataToolsReturnObject<T>> ExecuteStoredProcedure<T>(string StoredProcedureName, DynamicParameters p)
        {
            DataToolsReturnObject<T> obj = new DataToolsReturnObject<T>();
            obj.message = string.Empty;
            obj.error = string.Empty;

            try
            {
                DapperContext _context = new DapperContext(_config);
                obj.results = new List<T>();

                using (var connection = _context.CreateConnection())
                {
                    var reader = await connection.QueryAsync<T>(StoredProcedureName, p, null, null, System.Data.CommandType.StoredProcedure);
                    obj.results = reader.ToList<T>();
                    obj.message = "success";
                }
            }
            catch(Exception ex)
            {
                obj.error = ex.Message + "\n" + ex.StackTrace;
            }

            return obj;
        }
    }
}
