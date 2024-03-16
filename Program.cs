using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using HDS.AuthorizationServer;
using static OpenIddict.Abstractions.OpenIddictConstants;
using HDS.AuthorizationServer.Context;
using HDS.AuthorizationServer.Users;
using HDS.AuthorizationServer.Repository;
using HDS.AuthorizationServer.Classes;
using NLog;
using NLog.Web;

var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();

var builder = WebApplication.CreateBuilder(args);

string? ConnectString = builder.Configuration["ConnectionStrings:DefaultConnection"];

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(ConnectString);
    options.UseOpenIddict();
});

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
    });

builder.Services.AddTransient<AuthorizationService>();
builder.Services.AddSingleton<DapperContext>();
builder.Services.AddScoped<IUserRepository, UserRepository>();

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
    Uri UriCors1 = UriTools.BuildUri(builder.Configuration["HDSAuthorizationServer:UseSSL"],
        builder.Configuration["HDSAuthorizationServer:UriHost"],
        builder.Configuration["HDSAuthorizationServer:CorsPort1"],
        "");

    Uri UriCors2 = UriTools.BuildUri(builder.Configuration["HDSAuthorizationServer:UseSSL"],
        builder.Configuration["HDSAuthorizationServer:UriHost"],
        builder.Configuration["HDSAuthorizationServer:CorsPort2"],
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
