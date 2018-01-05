using Bonjour;
using System;
using System.Threading;
using System.Web.Http;
using System.Web.Http.SelfHost;
using System.Web.Http.Tracing;

namespace ColdBear.ConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            var t = new Thread(() =>
            {
                Thread.CurrentThread.IsBackground = true;

                DNSSDService service = new DNSSDService();

                TXTRecord txtRecord = new TXTRecord();
                txtRecord.SetValue("c#", "1");
                txtRecord.SetValue("ff", "0x01");
                txtRecord.SetValue("id", "AA:AA:AA:AA:AA:AA");
                txtRecord.SetValue("md", "Climenole1,0");
                txtRecord.SetValue("pv", "1.0");
                txtRecord.SetValue("s#", "1");
                txtRecord.SetValue("sf", "1");
                txtRecord.SetValue("ci", "2");

                var mgr = new DNSSDEventManager();
                mgr.RecordRegistered += Mgr_RecordRegistered;
                mgr.OperationFailed += Mgr_OperationFailed;
                mgr.ServiceRegistered += Mgr_ServiceRegistered;

                var record = service.Register(0, 0, "Climenole Bridge", "_hap._tcp", null, null, 51826, txtRecord, mgr);

                Console.WriteLine("Advertising Service in background thread");
            });
            t.Start();

            var config = new HttpSelfHostConfiguration("http://localhost:51826");

            config.Routes.MapHttpRoute("Pair Setup", "pair-setup", new { controller = "PairSetup" });
            config.Routes.MapHttpRoute("Identify", "identify", new { controller = "Identify" });
            config.Routes.MapHttpRoute("Pairings", "pairings", new { controller = "Pairings" });

            SystemDiagnosticsTraceWriter traceWriter = config.EnableSystemDiagnosticsTracing();
            traceWriter.IsVerbose = true;
            traceWriter.MinimumLevel = TraceLevel.Debug;

            using (var server = new HttpSelfHostServer(config))
            {
                server.OpenAsync().Wait();
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
