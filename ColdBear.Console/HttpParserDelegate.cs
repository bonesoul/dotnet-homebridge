using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using HttpMachine;

namespace ColdBear.ConsoleApp
{
    public class HttpParserDelegate : IHttpParserHandler
    {
        private string path;

        public void OnBody(HttpParser parser, ArraySegment<byte> data)
        {
            if(path == "pair-setup")
            {
                var controller = new PairSetupController();
                controller.Post(data.Array);
            }
        }

        public void OnFragment(HttpParser parser, string fragment)
        {
        }

        public void OnHeaderName(HttpParser parser, string name)
        {
        }

        public void OnHeadersEnd(HttpParser parser)
        {
        }

        public void OnHeaderValue(HttpParser parser, string value)
        {
        }

        public void OnMessageBegin(HttpParser parser)
        {
        }

        public void OnMessageEnd(HttpParser parser)
        {
        }

        public void OnMethod(HttpParser parser, string method)
        {
        }

        public void OnQueryString(HttpParser parser, string queryString)
        {
            
        }

        public void OnRequestUri(HttpParser parser, string requestUri)
        {
            var uri = new Uri(requestUri, UriKind.RelativeOrAbsolute);
            path = uri.Segments[0];
        }
    }
}
