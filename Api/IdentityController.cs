using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;

namespace Api
{
    /// <summary>
    /// Return all claims back to the caller - allows inspection of 
    /// the token supplied to the api
    /// </summary>
    [Route("Identity")]
    [Authorize]
    public class IdentityController : ApiController
    {
        public IHttpActionResult Get()
        {
            var user = User as ClaimsPrincipal;
            var claims = from c in user.Claims
                         select new
                         {
                             type = c.Type,
                             value = c.Value
                         };
            return Json(claims);
        }
    }
}