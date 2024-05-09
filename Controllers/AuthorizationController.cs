using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using HDS.AuthorizationServer;
using HDS.AuthorizationServer.Interfaces;
using HDS.AuthorizationServer.Models;
using HDS.AuthorizationServer.Classes;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using OpenIddict.Server.AspNetCore;
using System.Collections.Immutable;
using System.Net;
using System.Security.Claims;
using System.Web;
using HDS.AuthorizationServer.Repository;

namespace HDS.AuthorizationServer.Controllers
{
    [ApiController]
    public class AuthorizationController : Controller
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly AuthorizationService _authService;
        private readonly UserManager<IdentityUser<int>> _userManager;
        private readonly IAuthorizationRepository _authRepo;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger _logger;
        private readonly IConfiguration _config;

        public AuthorizationController(
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictScopeManager scopeManager,
            UserManager<IdentityUser<int>> userManager,
            IAuthorizationRepository authRepo,
            AuthorizationService authService,
            IHttpClientFactory httpClientFactory,
            ILogger<AuthorizationController> logger,
            IConfiguration config)
        {
            _applicationManager = applicationManager;
            _scopeManager = scopeManager;
            _authService = authService;
            _userManager = userManager;
            _authRepo = authRepo;
            _httpClientFactory = httpClientFactory;
            _logger = logger;
            _config = config;
        }

        [HttpGet("~/connect/authorize")]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                          throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ??
                              throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

            if (await _applicationManager.GetConsentTypeAsync(application) != ConsentTypes.Explicit)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidClient,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "Only clients with explicit consent type are allowed."
                    }));
            }

            var parameters = _authService.ParseOAuthParameters(HttpContext, new List<string> { Parameters.Prompt });

            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            if (!_authService.IsAuthenticated(result, request))
            {
                var claims = new List<Claim>();

                var principal = new ClaimsPrincipal(
                    new List<ClaimsIdentity>
                    {
                    new(claims, CookieAuthenticationDefaults.AuthenticationScheme)
                    });

                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                //get the authentication cookie
                var url = HttpContext.Request.GetEncodedUrl();

                string hdrAuthentication = Response.Headers["Set-Cookie"];
                string[] authenticationCookie = hdrAuthentication.Split("=");
                string name = authenticationCookie[0];
                string AuthenticationCode = "\"" + authenticationCookie[1] + "\"";

                //add the authentication cookie to the container

                var baseAddress = new Uri(HttpContext.Request.GetEncodedUrl());
                var cookieContainer = new CookieContainer();
                Cookie cookie = new Cookie(name, AuthenticationCode, "\\", baseAddress.Host);
                cookieContainer.Add(baseAddress, cookie);

                //now get the parameters
                var paramAuthorize = new Dictionary<string, string>();
                foreach (var param in parameters)
                {
                    string key = param.Key;
                    string value = param.Value;
                    paramAuthorize.Add(key, value);
                }

                //now try to Authorize again
                string ru = _authService.BuildRedirectUrl(HttpContext.Request, parameters);

                return Challenge(properties: new AuthenticationProperties
                {
                    RedirectUri = ru
                }, new[] { CookieAuthenticationDefaults.AuthenticationScheme });
            }

            if (request.HasPrompt(Prompts.Login))
            {
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                return Challenge(properties: new AuthenticationProperties
                {
                    RedirectUri = _authService.BuildRedirectUrl(HttpContext.Request, parameters)
                }, new[] { CookieAuthenticationDefaults.AuthenticationScheme });
            }

            var consentClaim = result.Principal.GetClaim(Consts.ConsentNaming);

            // it might be extended in a way that consent claim will contain list of allowed client ids.
            //L@@K - we need to figure out what to do with the claims
            //if (consentClaim != Consts.GrantAccessValue || request.HasPrompt(Prompts.Consent))
            //{
            //    await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            //    var returnUrl = HttpUtility.UrlEncode(_authService.BuildRedirectUrl(HttpContext.Request, parameters));
            //    var consentRedirectUrl = $"/Consent?returnUrl={returnUrl}";

            //    return Redirect(consentRedirectUrl);
            //}

            var userId = result.Principal.FindFirst(ClaimTypes.Email)!.Value;

            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            identity.SetClaim(Claims.Subject, userId)
                .SetClaim(Claims.Email, userId)
                .SetClaim(Claims.Name, userId)
                .SetClaims(Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());

            identity.SetScopes(request.GetScopes());
            identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
            identity.SetDestinations(c => AuthorizationService.GetDestinations(identity, c));

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }




        [HttpPost("~/connect/token")]
        public async Task<IActionResult> Exchange()
        {
            IdentityUser<int>? user = new IdentityUser<int>();
            AspNetUser aspnetuser = new AspNetUser();
            string UserEmail = string.Empty;
            string Password = string.Empty;

            try
            {

                var request = HttpContext.GetOpenIddictServerRequest() ??
                              throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

                if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
                    throw new InvalidOperationException("The specified grant type is not supported.");

                UserEmail = request.GetParameter("user").ToString();
                Password = request.GetParameter("password").ToString();
                user = await _userManager.FindByEmailAsync(UserEmail);
                aspnetuser = await _authRepo.GetUserByEmail(UserEmail);

                PasswordHasher<IdentityUser<int>> ph = new PasswordHasher<IdentityUser<int>>();

                PasswordVerificationResult rslt = ph.VerifyHashedPassword(user, aspnetuser.PasswordHash, Password);

                if (rslt != PasswordVerificationResult.Success)
                {
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "Username and password combination is not valid."
                        }));
                }
            }
            catch(Exception ex)
            {
                _logger.LogError("Exception encountered while validating password \n{0}\n{1}", ex.Message, ex.StackTrace);
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "Error attempting to validate password."
                    }));
            }

            //try
            //{
            //    //add 2FA check here
            //    if (string.IsNullOrEmpty(_config["Authentication:2FA_URL"]))
            //    {
            //        return Forbid(
            //            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            //            properties: new AuthenticationProperties(new Dictionary<string, string?>
            //            {
            //                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
            //                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
            //                "Error retrieving Authentication 2FA url."
            //            }));
            //    };

            //    TwoFactorResults tfr = await _authRepo.Generate2FA(user.Id);
            //    string msg2FA = string.Format(_config["Authentication:2FA_Message"], tfr.Code);
            //    string url2FA = string.Format(_config["Authentication:2FA_URL"], "user1", "user_pass", user.PhoneNumber, msg2FA);
            //    HttpClient client = _httpClientFactory.CreateClient();
            //    HttpResponseMessage msg = await client.GetAsync(url2FA);

            //    if (!msg.IsSuccessStatusCode)
            //    {
            //        _logger.LogError($"Error while trying to send 2FA code to UserID: {user.Id}");
            //    }
            //}
            //catch(Exception ex)
            //{
            //    _logger.LogError("Exception encountered during Two Factor Authentication. \n{0}\n{1}", ex.Message, ex.StackTrace);
            //    return Forbid(
            //        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            //        properties: new AuthenticationProperties(new Dictionary<string, string?>
            //        {
            //            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
            //            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
            //            "Error during Two Factor Authentication."
            //        }));

            //}

            List<CustomClaim> myClaims = await _authRepo.GetClaimsByEmail(UserEmail);

            var result =
                await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            var userId = result.Principal.GetClaim(Claims.Subject);

            if (string.IsNullOrEmpty(userId))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "Cannot find user from the token."
                    }));
            }

            var identity = new ClaimsIdentity(result.Principal.Claims,
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            identity.SetClaim(Claims.Subject, userId)
                .SetClaim(Claims.Email, userId)
                .SetClaim(Claims.Name, userId)
                .SetClaims(Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());

            foreach (var claim in myClaims)
            {
                identity.AddClaim(new Claim(claim.ClaimType, claim.ClaimValue));
            }

            identity.SetDestinations(c => AuthorizationService.GetDestinations(identity, c));
            ClaimsPrincipal principal = new ClaimsPrincipal(identity);
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
        [HttpGet("~/connect/userinfo"), HttpPost("~/connect/userinfo")]
        public async Task<IActionResult> Userinfo()
        {
            if (User.GetClaim(Claims.Subject) != Consts.Email)
            {
                return Challenge(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The specified access token is bound to an account that no longer exists."
                    }));
            }

            var claims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                // Note: the "sub" claim is a mandatory claim and must be included in the JSON response.
                [Claims.Subject] = Consts.Email
            };

            if (User.HasScope(Scopes.Email))
            {
                claims[Claims.Email] = Consts.Email;
            }

            return Ok(claims);
        }

        [HttpGet("~/connect/logout")]
        [HttpPost("~/connect/logout")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return SignOut(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = "/"
                });
        }
    }
}
