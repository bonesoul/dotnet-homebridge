using Newtonsoft.Json.Linq;
using System;
using System.Text;
using System.Web.Http;

namespace ColdBear.ConsoleApp
{
    public class AccessoriesController : ApiController
    {
        public Tuple<string, byte[]> Get(ControllerSession session)
        {
            JObject jObject = new JObject();
            jObject.Add("accessories", new JArray());

            var output = Encoding.UTF8.GetBytes(jObject.ToString());

            return new Tuple<string, byte[]>("application/hap+json", output);
        }
    }
}
