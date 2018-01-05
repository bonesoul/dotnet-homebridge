using System.Web.Http;

namespace ColdBear.ConsoleApp
{
    public class AccessoriesController : ApiController
    {
        public IHttpActionResult Get()
        {
            return StatusCode(System.Net.HttpStatusCode.Unauthorized);
        }
    }
}
