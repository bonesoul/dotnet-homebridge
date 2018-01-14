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
            Console.WriteLine("**************************");
            Console.WriteLine("* Accessories Controller *");
            Console.WriteLine("* List accessories       *");
            Console.WriteLine("**************************");

            var output = File.ReadAllBytes(@"C:\Development\dotnet-homebridge\ColdBear.Console\accessories.json");

            Console.WriteLine("Accessories JSON");
            Console.WriteLine(Encoding.UTF8.GetString(output));

            return new Tuple<string, byte[]>("application/hap+json", output);
        }
    }
}
