using Bonjour;
using Microsoft.Owin.Hosting;
using System;
using System.Threading;

namespace ColdBear.ConsoleApp
{
    class Program
    {
        public const string ID = "AC:22:3D:E3:CE:D6";

        static void Main(string[] args)
        {
           

            var t = new Thread(() =>
            {
                Thread.CurrentThread.IsBackground = true;

                DNSSDService service = new DNSSDService();

                TXTRecord txtRecord = new TXTRecord();
                txtRecord.SetValue("sf", "1");
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
            t.Start();

            string baseAddress = "http://*:51826/";

            StartOptions options = new StartOptions();
            options.Urls.Add("http://*:51826");

            using (WebApp.Start(baseAddress))
            {
                Console.WriteLine("Server started....");
                Console.WriteLine("Press Enter to quit.");
                Console.ReadLine();
            }

            t.Join();
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
