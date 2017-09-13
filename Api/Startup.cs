using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using System.Web.Http;
using IdentityServer3.AccessTokenValidation;
//https://identityserver.github.io/Documentation/docsv2/overview/mvcGettingStarted.html
[assembly: OwinStartup(typeof(Api.Startup))]
namespace Api
{
    /// <summary>
    /// This (example) Api will be secured by IdentityServer.
    /// I'll write further code such that MVC application will call the API
    /// using both the trust subsystem and identity delegation approach.
    /// </summary>
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=316888

            // To secure API using IdentityServer, two things are needed:
            // 1. Accept only tokens issued by the correct IdentityServer
            // 2. accept only tokens issued for this api e.e tokens with scope = "sampleApi".
            // This is accomplished using the IdentityServer3.AccessTokenValidation package.
            // NB IdentityServer3 issues standard Json Web Tokens: you could use plain Katana JWT middleware to validate them.
            // IdentityServer3.AccessTokenValidatio is more convenient: it auto-configures itself using IdentityServer discovery document (metadata).
            app.UseIdentityServerBearerTokenAuthentication(new IdentityServerBearerTokenAuthenticationOptions
            {
                Authority = "https://localhost:44370/identity",
                RequiredScopes = new[] { "sampleApi" }
            });

            // webapi configuration
            var config = new HttpConfiguration();
            config.MapHttpAttributeRoutes();
            app.UseWebApi(config);



        }
    }
}
