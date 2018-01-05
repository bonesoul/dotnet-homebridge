using Microsoft.Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ColdBear.ConsoleApp
{
    public class HeaderChangeMiddleware : OwinMiddleware
    {
        public HeaderChangeMiddleware(OwinMiddleware next) : base(next)
        {
        }

        public override Task Invoke(IOwinContext context)
        {
            // iOS is sending a long host name like Climenon._hap._tcp.local and URI doesn't like. It bombs out trying 
            // to parse it, which results in a 500 being returned.
            //
            // To work around this, I create a copy of the IOwinContext, and replace the headers. It's horrible, 
            // but was the only way I could make it work.
            //
            // At pesent, the content type and content-length headers are being lost, but SRP is a challeng in itself
            //
            var contextParms = new Dictionary<String, object>();

            foreach (var key in context.Environment)
            {
                contextParms.Add(key.Key, key.Value);
            }

            contextParms["owin.RequestHeaders"] = new Dictionary<string, string[]>() { { "Host", new string[1] { "localhost" } } };// existingHeaders;

            var newContext = new OwinContext(contextParms);

            return Next.Invoke(newContext);
        }
    }
}
