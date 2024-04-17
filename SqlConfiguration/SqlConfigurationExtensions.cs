using Microsoft.Extensions.Configuration;

namespace HDS.AuthorizationServer.SqlConfiguration
{
    public static class SqlDatabaseConfigurationExtensions
    {
        public static IConfigurationBuilder AddSqlDatabase(this IConfigurationBuilder builder, Action<SqlDatabaseConfigurationSource>? configurationSource)
            => builder.Add(configurationSource);
    }
}
