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
            context.Request.Host = new HostString("locahost");
            return Task.CompletedTask;
        }
    }
}
