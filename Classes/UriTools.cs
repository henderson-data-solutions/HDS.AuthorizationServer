using System.Text;

namespace HDS.AuthorizationServer.Classes
{
 
    public static class UriTools
    {

        public static Uri BuildUri(string UseSsl, string host, string port = "", string path = "")
        {
            StringBuilder sb = new StringBuilder("http");
            Uri uriNew = null;

            //check if UseSsl starts with a Y or a T
            if (UseSsl.ToLower().StartsWith('y') || UseSsl.ToLower().StartsWith('t'))
            {
                sb.Append('s');
            }

            sb.Append("://");

            sb.Append(host.Trim('/', ' ')); //remove any leading/trailing slashes or spaces from host

            if (!string.IsNullOrEmpty(port))
            {
                sb.Append(':');
                sb.Append(port.Trim(' '));
            }

            sb.Append('/');

            if (!string.IsNullOrEmpty(path))
            {
                sb.Append(path.Trim('/', ' '));
            }

            try
            {
                uriNew = new Uri(sb.ToString());
            }
            catch (Exception exc)
            {
                //add a logger and log the error her
            }
            return uriNew;
        }
    }
}