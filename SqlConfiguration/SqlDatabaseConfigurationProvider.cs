using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using HDS.AuthorizationServer.SqlConfiguration;
using Dapper;
using HDS.AuthorizationServer.Models;
using System.Data;
using System.Reflection.PortableExecutable;
using NLog;
using NLog.Web;

namespace HDS.AuthorizationServer.SqlConfiguration
{
    public class SqlDatabaseConfigurationProvider : ConfigurationProvider, IDisposable
    {
        private readonly Timer? _refreshTimer = null;

        public SqlDatabaseConfigurationSource Source { get; }

        public SqlDatabaseConfigurationProvider(SqlDatabaseConfigurationSource source)
        {
            Source = source;

            if (Source.RefreshInterval.HasValue)
                _refreshTimer = new Timer(_ => ReadDatabaseSettings(true), null, Timeout.Infinite, Timeout.Infinite);
        }

        public override void Load()
        {
            if (string.IsNullOrWhiteSpace(Source.ConnectionString))
                return;

            ReadDatabaseSettings(false);

            if (_refreshTimer != null && Source.RefreshInterval.HasValue)
                _refreshTimer.Change(Source.RefreshInterval.Value, Source.RefreshInterval.Value);
        }

        private void ReadDatabaseSettings(bool isReload)
        {
            var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();

            string procname = "GetConfigurationOptions";
            var settings = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
            List<ConfigurationOption> options = new List<ConfigurationOption>();

            logger.Info("Connection string: " + Source.ConnectionString);
            try
            {
                using (IDbConnection db = new SqlConnection(Source.ConnectionString))
                {
                    try
                    {
                        var results = db.Query<ConfigurationOption>(procname, commandType: CommandType.StoredProcedure);
                        options = results.ToList();
                    }
                    catch(Exception ex)
                    {
                        Console.WriteLine(ex.ToString());
                    }

                    foreach (ConfigurationOption option in options)
                    {
                        try
                        {
                            settings[option.SettingKey] = option.SettingValue;
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine(ex.Message + "\n" + ex.StackTrace);
                        }
                    }

                    if (!isReload || !SettingsMatch(Data, settings))
                    {
                        Data = settings;

                        if (isReload)
                            OnReload();
                    }
                }
            }
            catch (Exception sqlEx)
            {
                System.Diagnostics.Debug.WriteLine(sqlEx);
            }
        }

        private bool SettingsMatch(IDictionary<string, string?> oldSettings, IDictionary<string, string?> newSettings)
        {
            if (oldSettings.Count != newSettings.Count)
                return false;

            return oldSettings
                .OrderBy(s => s.Key)
                .SequenceEqual(newSettings.OrderBy(s => s.Key));
        }

        public void Dispose()
        {
            _refreshTimer?.Change(Timeout.Infinite, Timeout.Infinite);
            _refreshTimer?.Dispose();
        }
    }
}
