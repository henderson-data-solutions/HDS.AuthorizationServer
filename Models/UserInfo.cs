namespace HDS.AuthorizationServer.Models
{
    public class UserInfo
    {
        public AspNetUser user {  get; set; }
        public List<CustomClaim> claims { get; set; }
    }
}
