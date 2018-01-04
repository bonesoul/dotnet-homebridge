using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Zeroconf;

namespace ColdBear.HomeBridge
{
    public class Program
    {
        public static void Main(string[] args)
        {
            AdapterInformation info = new AdapterInformation("Aaron's DAAP Share","");
            //service.RegType = "_hap._tcp";
            //service.ReplyDomain = "local.";
            //service.Port = 3689;

            ServiceAnnouncement service = new ServiceAnnouncement(info, null);

            // TxtRecords are optional
            //TxtRecord txt_record = new TxtRecord();
            //txt_record.Add("Password", "false");
            //service.TxtRecord = txt_record;

            //service.Register();

            BuildWebHost(args).Run();
        }

        public static IWebHost BuildWebHost(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseStartup<Startup>()
                .Build();
    }
}
