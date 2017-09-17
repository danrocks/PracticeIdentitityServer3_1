using IdentityModel.Client;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace PracticeIdentitityServer3_1.Controllers
{

    /// <summary>
    /// Calling an APi requires two steps:
    /// Request a token for the API from IdentityServer(using the client credentials)
    /// Call the Api usig the access token.
    /// IdentityServer3 has the "IdentityModel" client package that makes interaction with the 
    /// OAuth2 token endpoint easier.
    /// </summary>
    public class CallApiController : Controller
    {
        //GET: Call/Api/ClientCredentials
        // Invoke the Api project's Identity controller (using ClientCredentials)
        public async Task<ActionResult> ClientCredentials(){
            var response = await GetTokenAsync();
            var result = await CallApi(response.AccessToken);
            ViewBag.Json = result;
            return View("ShowApiResult");
        }

        /// <summary>
        /// Request token fo sampleApi using client credentials.
        /// Remember this example is a bit contrived: this MVC web application
        /// is being used to call our Api example but it also has IdentityServer3
        /// built in.
        /// </summary>
        /// <returns></returns> 
        private async Task<TokenResponse> GetTokenAsync() {
            var client = new TokenClient(
                    "https://localhost:44370/identity/connect/token",
                    "mvc_service",
                    "secret"
                );
            return await client.RequestClientCredentialsAsync("sampleApi");
        }

        /// <summary>
        /// calls identity endpoint using the requested access token
        /// </summary>
        /// <param name="Token"></param>
        /// <returns></returns>
        private async Task<string> CallApi(string token) {
            var client = new HttpClient();
            client.SetBearerToken(token);
            // port number of Api, which has an IdentityController
            var json = await client.GetStringAsync("https://localhost:44329/identity");
            return JArray.Parse(json).ToString();
        }
    }
}