using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Text;
using System.Web.Http;

namespace ColdBear.ConsoleApp
{
    public class AccessoriesController : ApiController
    {
        public Tuple<string, byte[]> Get(ControllerSession session)
        {
            var output = File.ReadAllBytes("accessories.json");
            return new Tuple<string, byte[]>("application/hap+json", output);
        }
    }
}
