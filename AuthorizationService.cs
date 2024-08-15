using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;

namespace HDS.AuthorizationServer;

public class AuthorizationService
{
    public IDictionary<string, StringValues> ParseOAuthParameters(HttpContext httpContext, List<string>? excluding = null)
    {
        excluding ??= new List<string>();

        var parameters = httpContext.Request.HasFormContentType
            ? httpContext.Request.Form
                .Where(v => !excluding.Contains(v.Key))
                .ToDictionary(v => v.Key, v => v.Value)
            : httpContext.Request.Query
                .Where(v => !excluding.Contains(v.Key))
                .ToDictionary(v => v.Key, v => v.Value);

        return parameters;
    }

    public string BuildRedirectUrl(HttpRequest request, IDictionary<string, StringValues> oAuthParameters)
    {
        var url = request.PathBase + request.Path + QueryString.Create(oAuthParameters);
        return url;
    }

    public bool IsAuthenticated(AuthenticateResult authenticateResult, OpenIddictRequest request)
    {
        if (!authenticateResult.Succeeded)
        {
            return false;
        }

        if (request.MaxAge.HasValue && authenticateResult.Properties != null)
        {
            var maxAgeSeconds = TimeSpan.FromSeconds(request.MaxAge.Value);

            var expired = !authenticateResult.Properties.IssuedUtc.HasValue ||
                          DateTimeOffset.UtcNow - authenticateResult.Properties.IssuedUtc > maxAgeSeconds;
            if (expired)
            {
                return false;
            }
        }

        return true;
    }

    public static List<string> GetDestinations(ClaimsIdentity identity, Claim claim)
    {
        var destinations = new List<string>();
        //L@@K need to replace the hard coded values below by 
        //searching the db for all claims in AspNetUserClaims
        if (claim.Type is OpenIddictConstants.Claims.Name 
            or OpenIddictConstants.Claims.Email
            or OpenIddictConstants.Claims.Address
            or "System.Admin"
            or "Invoice.Admin"
            or "Invoice.Read"
            or "Invoice.ReadWrite"
            or "User.Read" 
            or "User.ReadWrite"
            or "User.Admin")
        {
            destinations.Add(OpenIddictConstants.Destinations.AccessToken);

            if (identity.HasScope(OpenIddictConstants.Scopes.OpenId))
            {
                destinations.Add(OpenIddictConstants.Destinations.IdentityToken);
            }
        }

        return destinations;
    }
}