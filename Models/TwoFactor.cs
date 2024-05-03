namespace HDS.AuthorizationServer.Models
{
    public class TwoFactorResults
    {
        public string? Code { get; set; }
        public Guid? Lookup {  get; set; } 

    }
}
