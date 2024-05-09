﻿namespace HDS.AuthorizationServer.Classes
{
    public class HDSAuthorizationResult
    {
        public int status { get; set; }
        public string message { get; set; }
        public string access_token { get; set; }
        public string code { get; set; }
        public string iss { get; set; }
        public string state { get; set; }
        public Guid twofactorlookup {  get; set; }  


        public HDSAuthorizationResult()
        {
            status = 0;
            message = string.Empty;
            access_token = string.Empty;
            code = string.Empty;
            iss = string.Empty;
            state = string.Empty;
        }
    }
}
