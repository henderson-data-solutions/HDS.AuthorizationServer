using HDS.AuthorizationServer;
using HDS.AuthorizationServer.Classes;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static System.Net.WebRequestMethods;

namespace HDS.AuthorizationServer
{
    public class ClientsSeeder
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IConfiguration _config;
        private readonly ILogger _logger;

        public ClientsSeeder(IServiceProvider serviceProvider, IConfiguration configuration, ILogger<ClientsSeeder> logger)
        {
            _serviceProvider = serviceProvider;
            _config = configuration;
            _logger = logger;

        }

        public async Task AddScopes()
        {
            _logger.LogInformation("AddScopes starting");
            await using var scope = _serviceProvider.CreateAsyncScope();
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

            var apiScope = await manager.FindByNameAsync("api1");

            if (apiScope != null)
            {
                await manager.DeleteAsync(apiScope);
            }

            await manager.CreateAsync(new OpenIddictScopeDescriptor
            {
                DisplayName = "Api scope",
                Name = "api1",
                Resources =
                {
                    "resource_server_1"
                }
            });
        }

        public async Task AddWebClient()
        {
            _logger.LogInformation("AddWebClient add client [web-client]");

            await using var scope = _serviceProvider.CreateAsyncScope();

            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await context.Database.EnsureCreatedAsync();

            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            var client = await manager.FindByClientIdAsync("web-client");
            if (client != null)
            {
                await manager.DeleteAsync(client);
            }

            Uri RedirectUri = UriTools.BuildUri(
                _config["HDSInvoiceServer:UseSSL"],
                _config["HDSInvoiceServer:UriHost"],
                _config["HDSInvoiceServer:UriPort"],
                _config["HDSInvoiceServer:AuthRedirectPath"]);

            Uri SwaggerRedirectUri = UriTools.BuildUri(
                _config["HDSInvoiceServer:UseSSL"],
                _config["HDSInvoiceServer:UriHost"],
                _config["HDSInvoiceServer:UriPort"],
                _config["HDSInvoiceServer:SwaggerRedirectPath"]);

            Uri LogoutRedirectUri = UriTools.BuildUri(
                _config["HDSInvoiceServer:UseSSL"],
                _config["HDSInvoiceServer:UriHost"],
                _config["HDSInvoiceServer:UriPort"],
                _config["HDSInvoiceServer:LogoutRedirectPath"]);

            _logger.LogInformation($"AddWebClient set redirect uri [{RedirectUri.ToString()}]");
            _logger.LogInformation($"AddWebClient set redirect uri [{SwaggerRedirectUri.ToString()}]");
            _logger.LogInformation($"AddWebClient set logout redirect uri [{LogoutRedirectUri}]");
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = _config["Authentication:client_id"],
                ClientSecret = _config["Authentication:client_secret"],
                ConsentType = ConsentTypes.Explicit,
                DisplayName = _config["Authentication:DisplayName"],
                RedirectUris =
                {
                    new Uri(SwaggerRedirectUri.ToString()),
                    new Uri(RedirectUri.ToString()),
                    new Uri("https://localhost:44319/Account/Login"),
                    new Uri("https://invoice.hds.com/Account/Login"),
                    new Uri("https://app1.hds.com/Account/Login"),
                    new Uri("https://localhost/Account/Login")
                },
                PostLogoutRedirectUris =
                {
                    new Uri(LogoutRedirectUri.ToString())
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Logout,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                   $"{Permissions.Prefixes.Scope}api1"
                },
                //Requirements =
                //{
                //    Requirements.Features.ProofKeyForCodeExchange
                //}
            });
        }

        public async Task AddOidcDebuggerClient()
        {
            await using var scope = _serviceProvider.CreateAsyncScope();

            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await context.Database.EnsureCreatedAsync();

            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            var client = await manager.FindByClientIdAsync("oidc-debugger");
            if (client != null)
            {
                await manager.DeleteAsync(client);
            }

            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "oidc-debugger",
                ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
                ConsentType = ConsentTypes.Explicit,
                DisplayName = "Postman client application",
                RedirectUris =
                {
                    new Uri("https://oidcdebugger.com/debug")
                },
                PostLogoutRedirectUris =
                {
                    new Uri("https://oauth.pstmn.io/v1/callback")
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Logout,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                   $"{Permissions.Prefixes.Scope}api1"
                },
                //Requirements =
                //{
                //    Requirements.Features.ProofKeyForCodeExchange
                //}
            });
        }

        public async Task AddReactClient()
        {
            await using var scope = _serviceProvider.CreateAsyncScope();

            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await context.Database.EnsureCreatedAsync();

            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            var reactClient = await manager.FindByClientIdAsync("react-client");
            if (reactClient != null)
            {
                await manager.DeleteAsync(reactClient);
            }

            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "react-client",
                ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
                ConsentType = ConsentTypes.Explicit,
                DisplayName = "React client application",
                RedirectUris =
                {
                    new Uri("http://localhost:3000/oauth/callback")
                },
                PostLogoutRedirectUris =
                {
                    new Uri("http://localhost:3000/")
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Logout,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    $"{Permissions.Prefixes.Scope}api1"
                },
                //Requirements =
                //{
                //    Requirements.Features.ProofKeyForCodeExchange
                //}
            });
        }
    }
}

