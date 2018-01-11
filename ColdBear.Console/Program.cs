using Bonjour;
using Microsoft.Owin.Hosting;
using System;
using System.Threading;

namespace ColdBear.ConsoleApp
{
    class Program
    {
        public const string ID = "A2:22:3D:E3:CE:D6";

        static void Main(string[] args)
        {
            var t1 = new Thread(() =>
            {
                Thread.CurrentThread.IsBackground = true;

                DNSSDService service = new DNSSDService();

                TXTRecord txtRecord = new TXTRecord();
                txtRecord.SetValue("sf", "1"); // 1 means discoverable. 0 means it has been paired.
                txtRecord.SetValue("ff", "0x00");
                txtRecord.SetValue("ci", "2");
                txtRecord.SetValue("id", ID);
                txtRecord.SetValue("md", "Climenole");
                txtRecord.SetValue("s#", "1");
                txtRecord.SetValue("c#", "1");

                var mgr = new DNSSDEventManager();
                mgr.RecordRegistered += Mgr_RecordRegistered;
                mgr.OperationFailed += Mgr_OperationFailed;
                mgr.ServiceRegistered += Mgr_ServiceRegistered;

                var record = service.Register(0, 0, "Climenole", "_hap._tcp", null, null, 51826, txtRecord, mgr);

                Console.WriteLine("Advertising Service in background thread");
            });
            t1.Start();

            string baseAddress = "http://*:51826/";

            StartOptions options = new StartOptions();
            options.Urls.Add("http://*:51826");

            using (WebApp.Start(baseAddress))
            {
                Console.WriteLine("Server started....");
                Console.WriteLine("Press Enter to quit.");
                Console.ReadLine();
            }

            //var t2 = new Thread(() =>
            //{
            //    IPAddress address = IPAddress.Any;
            //    IPEndPoint port = new IPEndPoint(address, 51826); //port 9999

            //    TcpListener listener = new TcpListener(port);

            //    listener.Start();

            //    Console.WriteLine("--Server Started--");

            //    while (true) //loop forever
            //    {
            //        Console.WriteLine("Waiting for New Controller to connect");
            //        Socket sock = listener.AcceptSocket();

            //        Console.WriteLine($"Controller has connected on {sock.Handle}!");

            //        byte[] buffer = new byte[32];

            //        string incomingMessage = "";

            //        //read:
            //        while (sock.Available > 0)
            //        {
            //            int gotBytes = sock.Receive(buffer);
            //            incomingMessage += Encoding.ASCII.GetString(buffer, 0, gotBytes);
            //        }

            //        //debugging:
            //        //Console.WriteLine(incomingMessage);

            //        //Now check whether its a GET or a POST

            //        if (incomingMessage.ToUpper().Contains("POST") && incomingMessage.ToUpper().Contains("/Pair-Setup")) //a search has been asked for
            //        {
            //            Console.WriteLine("Query Has Been Received");

            //            //extracting the post data

            //            string htmlPostData = incomingMessage.Substring(incomingMessage.IndexOf("songName"));

            //            string[] parameters = htmlPostData.Split('&');

            //            string[] inputs = new string[5];

            //            for (int i = 0; i < parameters.Length; i++)
            //            {
            //                inputs[i] = (parameters[i].Split('='))[1];
            //                inputs[i] = inputs[i].Replace('+', ' ');
            //            }
            //        }
            //    }
            //});

            //t2.Start();


            //Console.WriteLine("Press any key to terminate");
            //Console.ReadKey();

            //context.
            t1.Join();
            //t2.Join();
        }

        private static void Mgr_ServiceRegistered(DNSSDService service, DNSSDFlags flags, string name, string regtype, string domain)
        {
            Console.WriteLine("Service registered");
        }

        private static void Mgr_OperationFailed(DNSSDService service, DNSSDError error)
        {
            Console.WriteLine("Operation failed");
        }

        private static void Mgr_RecordRegistered(DNSSDRecord record, DNSSDFlags flags)
        {
            Console.WriteLine("Record registered");
        }
    }
}
