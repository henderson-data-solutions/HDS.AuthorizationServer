using Microsoft.Extensions.Configuration;
using HDS.AuthorizationServer.SqlConfiguration;

namespace HDS.AuthorizationServer.SqlConfiguration
{
    public class SqlDatabaseConfigurationSource : IConfigurationSource
    {
        public string? ConnectionString { get; set; }
        public TimeSpan? RefreshInterval { get; set; }

        public IConfigurationProvider Build(IConfigurationBuilder builder)
            => new SqlDatabaseConfigurationProvider(this);
    }
}
