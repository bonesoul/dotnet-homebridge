using Bonjour;
using System;
using System.Threading;

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
                txtRecord.SetValue("c#", 1);
                txtRecord.SetValue("ff", 0x01);
                txtRecord.SetValue("id", "AA:AA:AA:AA:AA:AA");
                txtRecord.SetValue("md", "Jarvis1,0");
                txtRecord.SetValue("pv", "1.0");
                txtRecord.SetValue("s#", "1");
                txtRecord.SetValue("sf", 0x01);
                txtRecord.SetValue("c1", 2);

                var mgr = new DNSSDEventManager();
                mgr.RecordRegistered += Mgr_RecordRegistered;
                mgr.OperationFailed += Mgr_OperationFailed;
                mgr.ServiceRegistered += Mgr_ServiceRegistered;

                var record = service.Register(0, 0, "Jarvis Bridge", "_hap._tcp", null, null, 80, txtRecord, mgr);

                Console.WriteLine("Advertising Service in background thread");
            });
            t.Start();

            Console.WriteLine("Press any key to close console");
            Console.ReadKey();

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
