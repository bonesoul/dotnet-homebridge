using Owin;
using System.Web.Http;
using System.Web.Http.Tracing;

namespace ColdBear.ConsoleApp
{
    public class Startup
    {
        public void Configuration(IAppBuilder appBuilder)
        {
            var config = new HttpConfiguration();

            config.Routes.MapHttpRoute("Pair Setup", "pair-setup", new { controller = "PairSetup" });
            config.Routes.MapHttpRoute("Identify", "identify", new { controller = "Identify" });
            config.Routes.MapHttpRoute("Pairings", "pairings", new { controller = "Pairings" });
            config.Routes.MapHttpRoute("Accessories", "accessories", new { controller = "Accessories" });

            SystemDiagnosticsTraceWriter traceWriter = config.EnableSystemDiagnosticsTracing();
            traceWriter.IsVerbose = true;
            traceWriter.MinimumLevel = TraceLevel.Debug;

            appBuilder.Use(typeof(HeaderChangeMiddleware));

            appBuilder.UseWebApi(config);
        }
    }
}
