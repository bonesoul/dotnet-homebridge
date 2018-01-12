using System;
using HttpMachine;

namespace ColdBear.ConsoleApp
{
    public class HttpParserDelegate : IHttpParserHandler
    {
        private string currentPath = null;

        public void OnBody(HttpParser parser, ArraySegment<byte> data)
        {
            if (currentPath == "pair-setup")
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
            Console.WriteLine($"Method: {method}");
        }

        public void OnQueryString(HttpParser parser, string queryString)
        {

        }

        public void OnRequestUri(HttpParser parser, string requestUri)
        {
            Console.WriteLine($"Uri: {requestUri}");

            currentPath = requestUri.TrimStart('/');

            Console.WriteLine($"Path is: {currentPath}");
        }
    }
}
