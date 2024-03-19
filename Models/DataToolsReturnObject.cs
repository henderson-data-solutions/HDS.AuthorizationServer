namespace HDS.AuthorizationServer.Models
{
    public class DataToolsReturnObject<T>
    {
        public string error { get; set; }  
        public string message {  get; set; }
        public List<T> results { get; set; }

        public DataToolsReturnObject()
        {

        }
    }
}
