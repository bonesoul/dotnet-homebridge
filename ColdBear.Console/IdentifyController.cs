using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;

namespace ColdBear.ConsoleApp
{
    public class IdentifyController : ApiController
    {
        public IHttpActionResult Post()
        {
            return StatusCode(System.Net.HttpStatusCode.NoContent);
        }
    }
}
