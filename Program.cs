using HDS.AuthorizationServer;
using HDS.AuthorizationServer.Classes;
using HDS.AuthorizationServer.Context;
using HDS.AuthorizationServer.Interfaces;
using HDS.AuthorizationServer.Models;
using HDS.AuthorizationServer.Repository;
using HDS.AuthorizationServer.SqlConfiguration;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Abstractions.OpenIddictConstants;
using NLog;
using NLog.Web;

var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();

var builder = WebApplication.CreateBuilder(args);

logger.Info("1 connectionstring: " + builder.Configuration["ConnectionStrings:DefaultConnection"]);

builder.Configuration.AddSqlDatabase(config =>
{
    //We can get the connection string from previously added ConfigurationProviders to use in setting this up
    config.ConnectionString = builder.Configuration["ConnectionStrings:DefaultConnection"];
    config.RefreshInterval = TimeSpan.FromMinutes(1);
});

logger.Info("2 connectionstring: " + builder.Configuration["ConnectionStrings:DefaultConnection"]);

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration["ConnectionStrings:DefaultConnection"]);
    options.UseOpenIddict();
});

logger.Info("buider.Services/Configure");

//Settings from all sources will be merged together. Since the database provider is added after the default
//providers it can be used to override settings from those other providers.
builder.Services.Configure<ConfigurationOption>(builder.Configuration.GetSection("AppSettings"));

logger.Info("AddOpenIddict()");


builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
                .UseDbContext<ApplicationDbContext>();
    })
    .AddServer(options =>
    {
        options.SetAuthorizationEndpointUris("connect/authorize")
                .SetLogoutEndpointUris("connect/logout")
                .SetTokenEndpointUris("connect/token")
                .SetUserinfoEndpointUris("connect/userinfo");

        options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles);

        options.AllowAuthorizationCodeFlow();

        options.AddEncryptionKey(new SymmetricSecurityKey(
            Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));

        options.AddDevelopmentEncryptionCertificate()
                .AddDevelopmentSigningCertificate();

        options.UseAspNetCore()
                .EnableAuthorizationEndpointPassthrough()
                .EnableLogoutEndpointPassthrough()
                .EnableTokenEndpointPassthrough()
                .EnableUserinfoEndpointPassthrough();

        options.DisableAccessTokenEncryption();
    });

builder.Services.AddTransient<AuthorizationService>();
builder.Services.AddSingleton<DapperContext>();
builder.Services.AddScoped<IAuthorizationRepository, AuthorizationRepository>();

builder.Services.AddControllers();
builder.Services.AddRazorPages();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(c =>
    {
        c.LoginPath = "/Authenticate";
    });

builder.Services.AddTransient<ClientsSeeder>();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();



builder.Services.AddCors(options =>
{
    Uri UriCors1 = UriTools.BuildUri(builder.Configuration["HDSInvoiceServer:UseSSL"],
        builder.Configuration["HDSInvoiceServer:UriHost"],
        builder.Configuration["HDSInvoiceServer:CorsPort1"],
        "");

    Uri UriCors2 = UriTools.BuildUri(builder.Configuration["HDSInvoiceServer:UseSSL"],
        builder.Configuration["HDSInvoiceServer:UriHost"],
        builder.Configuration["HDSInvoiceServer:CorsPort2"],
        "");

    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins(UriCors1.ToString())
            .AllowAnyHeader();
        
        policy.WithOrigins(UriCors2.ToString())
            .AllowAnyHeader();
    });
});

builder.Services.AddDefaultIdentity<IdentityUser<int>>(options => options.SignIn.RequireConfirmedAccount = true)  
    .AddRoles<IdentityRole<int>>()  //add the role service.  
    .AddEntityFrameworkStores<ApplicationDbContext>();

builder.Logging.ClearProviders();
builder.Host.UseNLog();
builder.Services.AddHttpClient();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var seeder = scope.ServiceProvider.GetRequiredService<ClientsSeeder>();
    
    seeder.AddOidcDebuggerClient().GetAwaiter().GetResult();
    seeder.AddWebClient().GetAwaiter().GetResult();
    seeder.AddReactClient().GetAwaiter().GetResult();
    
    seeder.AddScopes().GetAwaiter().GetResult();
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseCors();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapRazorPages();

app.Run();
