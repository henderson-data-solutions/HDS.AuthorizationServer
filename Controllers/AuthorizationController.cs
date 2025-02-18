﻿using HDS.AuthorizationServer.Classes;
using HDS.AuthorizationServer.Interfaces;
using HDS.AuthorizationServer.Models;
using HDS.AuthorizationServer.Repository;
using HDS.AuthorizationServer;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;
using System.Collections.Immutable;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Web;

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

        //[HttpGet("~/connect/TwoFactorVerify")]
        //public async Task<IActionResult> TwoFactoryVerify()
        //{

        //}


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

            //var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            //if (!_authService.IsAuthenticated(result, request))
            //{
            //    var claims = new List<Claim>();

            //    var principal = new ClaimsPrincipal(
            //        new List<ClaimsIdentity>
            //        {
            //        new(claims, CookieAuthenticationDefaults.AuthenticationScheme)
            //        });

            //    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

            //    //get the authentication cookie
            //    var url = HttpContext.Request.GetEncodedUrl();

            //    string hdrAuthentication = Response.Headers["Set-Cookie"];
            //    string[] authenticationCookie = hdrAuthentication.Split("=");
            //    string name = authenticationCookie[0];
            //    string AuthenticationCode = "\"" + authenticationCookie[1] + "\"";

            //    //add the authentication cookie to the container

            //    var baseAddress = new Uri(HttpContext.Request.GetEncodedUrl());
            //    var cookieContainer = new CookieContainer();
            //    Cookie cookie = new Cookie(name, AuthenticationCode, "\\", baseAddress.Host);
            //    cookieContainer.Add(baseAddress, cookie);

            //    //now get the parameters
            //    var paramAuthorize = new Dictionary<string, string>();
            //    foreach (var param in parameters)
            //    {
            //        string key = param.Key;
            //        string value = param.Value;
            //        paramAuthorize.Add(key, value);
            //    }

            //    //now try to Authorize again
            //    string ru = _authService.BuildRedirectUrl(HttpContext.Request, parameters);

            //    return Challenge(properties: new AuthenticationProperties
            //    {
            //        RedirectUri = ru
            //    }, new[] { CookieAuthenticationDefaults.AuthenticationScheme });
            //}

            if (request.HasPrompt(Prompts.Login))
            {
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                return Challenge(properties: new AuthenticationProperties
                {
                    RedirectUri = _authService.BuildRedirectUrl(HttpContext.Request, parameters)
                }, new[] { CookieAuthenticationDefaults.AuthenticationScheme });
            }

            //var consentClaim = result.Principal.GetClaim(Consts.ConsentNaming);

            // it might be extended in a way that consent claim will contain list of allowed client ids.
            //L@@K - we need to figure out what to do with the claims
            //if (consentClaim != Consts.GrantAccessValue || request.HasPrompt(Prompts.Consent))
            //{
            //    await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            //    var returnUrl = HttpUtility.UrlEncode(_authService.BuildRedirectUrl(HttpContext.Request, parameters));
            //    var consentRedirectUrl = $"/Consent?returnUrl={returnUrl}";

            //    return Redirect(consentRedirectUrl);
            //}

            string userId = parameters["username"];


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

            bool remember;
            if (!bool.TryParse(parameters["remember"], out remember))
            {
                remember = false;
            }

            int AccessTokenExtendedLifetime;
            int AccessTokenDefaultLifetime;

            if(!Int32.TryParse(_config["Authentication:AccessTokenLifetimeExtendedInHours"], out AccessTokenExtendedLifetime))
            {
                _logger.LogError("Config setting Authentication:AccessTokenLifetimeExtendedInHours is not an integer. Setting to default value of 24.");
                AccessTokenExtendedLifetime = 24;
            }

            if (!Int32.TryParse(_config["Authentication:AccessTokenLifetimeDefaultInHours"], out AccessTokenDefaultLifetime)) 
            {
                _logger.LogError("Authentication:AccessTokenLifetimeDefaultInHours is not an integer. Setting to default value of 1.");
                AccessTokenDefaultLifetime = 1;
            }

            if (remember)
            {
                //remember is checked so keep user logged in for extended period of time
                identity.SetAccessTokenLifetime(TimeSpan.FromHours(AccessTokenExtendedLifetime));
                identity.SetIdentityTokenLifetime(TimeSpan.FromHours(AccessTokenExtendedLifetime));
            }
            else
            {
                //remember is not checked so set default access token lifetime
                identity.SetAccessTokenLifetime(TimeSpan.FromHours(AccessTokenDefaultLifetime));
                identity.SetIdentityTokenLifetime(TimeSpan.FromHours(AccessTokenDefaultLifetime));
            }

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpPost("~/connect/token")]
        public async Task<IActionResult> Exchange()
        {
            IdentityUser<int>? user = new IdentityUser<int>();
            AspNetUser aspnetuser = new AspNetUser();
            TwoFactorResults tfr = new TwoFactorResults();
            string UserEmail = string.Empty;
            string Password = string.Empty;
            HDSAuthorizationResult HDSAuthResult = new HDSAuthorizationResult();

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

                PasswordVerificationResult PVResult = ph.VerifyHashedPassword(user, aspnetuser.PasswordHash, Password);

                if (PVResult != PasswordVerificationResult.Success)
                {
                    HDSAuthResult.status = 403; //forbidden
                    HDSAuthResult.message = "Username and password combination is not valid.";
                    return new JsonResult(HDSAuthResult);
                }
            }
            catch (Exception ex)
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

            ClaimsPrincipal principal = await GetClaims(user.Id);
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        private async Task<ClaimsPrincipal> GetClaims(int UserID)
        {
            IdentityUser<int>? user = new IdentityUser<int>();
            AspNetUser aspnetuser = new AspNetUser();
            TwoFactorResults tfr = new TwoFactorResults();
            string UserEmail = string.Empty;
            string Password = string.Empty;
            HDSAuthorizationResult HDSAuthResult = new HDSAuthorizationResult();

            var request = HttpContext.Request;

            user = await _userManager.FindByIdAsync(UserID.ToString());
            aspnetuser = await _authRepo.GetUserByEmail(user.Email);
            List<CustomClaim> myClaims = await _authRepo.GetClaimsByEmail(user.Email);

            var result =
                await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            var userId = result.Principal.GetClaim(Claims.Subject);

            if (string.IsNullOrEmpty(userId))
            {
                return null;
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

            return principal;
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
