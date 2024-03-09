namespace Oidc.OpenIddict.AuthorizationServer.Classes
{
    public class HDSAuthorizationResult
    {
        public int status {  get; set; }
        public string message { get; set; }
        public string code { get; set; }
        public string access_token { get; set; }
    }
}
