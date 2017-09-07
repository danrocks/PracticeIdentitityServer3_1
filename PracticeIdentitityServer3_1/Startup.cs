using IdentityServer3.Core.Configuration;
using IdentityServer3.Core.Resources;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using System.Web.Helpers;
using static IdentityServer3.Core.Constants;
using System.Security.Claims;
using IdentityServer3.Core;
using Microsoft.Owin.Security;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;


//[assembly: OwinStartup(typeof(PracticeIdentitityServer3_1.Startup))]
namespace PracticeIdentitityServer3_1
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // Adjust the configuration for anti-CSRF protection to the new unique sub claim type
            // This isi necessary to allow the subsequent change on JwtSecurityTokenHandler.InboundClaimTypeMap
            AntiForgeryConfig.UniqueClaimTypeIdentifier = Constants.ClaimTypes.Subject;
            // the following changes behaviour of clain mapper so the names of calims
            // become much simpler.
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            app.Map("/identity", idsrvApp =>
            {
                idsrvApp.UseIdentityServer(new IdentityServerOptions
                {
                    SiteName = "Embedded IdentityServer",
                    SigningCertificate = LoadCertificate(),

                    Factory = new IdentityServerServiceFactory()
                                .UseInMemoryUsers(Users.Get())
                                .UseInMemoryClients(Clients.Get())
                                .UseInMemoryScopes(Scopes.Get())
                });

                // if we wanted to allow access via a 3rd party id provider e.g google
                // install install-package Microsoft.Owin.Security.Google
                // we might put the google config code in a ConfigureIdentityProviders method
                // and point to it from here:
                //AuthenticationOptions = new IdentityServer3.Core.Configuration.AuthenticationOptions
                //{
                //    IdentityProviders = ConfigureIdentityProviders
                //}
                //I think the point here is google could provide authentication but other features
                //of Identity Server 3 would handle authorization.
            });

            // Wire-up AuthorizationManager 
            // (for controller action with Teinkecture.IdentityServer REsourceAuthorize attribute)
            // Implementers can stick with MVC Authorize attribute. Note this can lead to infinite loops
            // where users are authenticated but do not belong to role that allows Authorize to pass.
            // Authorize sets action result to 401, which triggers redirect to IdentityServer, which redirects users back to same place...
            // Work-around is to override (class)AuthorizeAttribute's HandleUnauthorizedRequest method.
            // to return 403 (we know who you are, but you haven't been granted access)
            app.UseResourceAuthorization(new AuthorizationManager());

            // set-up cookie middleware
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "Cookies"
            });

            //1. ResponseType = "id_token" equates to standard OAuth2 implicit flow 
            //2. By default the OIDC middleware asks for two scopes: openid and profile - 
            // this is why IdentityServer includes the subject and name claims. 
            // added a request to the roles scope - it will be shown on the ABout page (which is programmed to show all scopes).
            // A browser restart maybe required  the new roles will not be in a previously created token.
            //3. The arriving token will contain low level protocol claims not reuired by the business logic.
            // You may take the incoming claims, decide which claims you want to keep and maybe need to contact additional 
            // data stores to retrieve more claims that are required by the application.
            // This process of turning incoming claims into application specific logic is called
            // "claims transformation"
            // OIDC middleware has a "notification" (SecurityTokenValidated) where you can do claims transformation -
            // the resulting claims will be stored in acookie
            //4. The example had UseTokenLifetime = false - dont know what it does yet.
            // see here -https://github.com/IdentityServer/IdentityServer3/issues/1653
            //5. If we want to do redirect when logging out, handle the RedirectToIdentityProvider notification
            // and make sure the token will be passed along.
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                Authority = "https://localhost:44370/identity",
                ClientId = "mvc",
                Scope = "openid profile roles",
                RedirectUri = "https://localhost:44370/",
                ResponseType = "id_token",

                SignInAsAuthenticationType = "Cookies",
                UseTokenLifetime = false,

                //OpenIdConnectAuthenticationNotifications specifies events which the
                //OpenIdConnectAuthenticationMiddleware invokes to enable developer control over the authentication process
                //Handlers for these events are set-up via the notifcations property
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    //Invoked after the security token has passed validation and a ClaimsIdentity has been generated.
                    SecurityTokenValidated = n =>
                    {
                        var id = n.AuthenticationTicket.Identity;

                        // we want to keep first name, last name, subject and roles
                        var givenName = id.FindFirst(Constants.ClaimTypes.GivenName);
                        var familyName = id.FindFirst(Constants.ClaimTypes.FamilyName);
                        var sub = id.FindFirst(Constants.ClaimTypes.Subject);
                        var roles = id.FindAll(Constants.ClaimTypes.Role);

                        // create new identity and set name and role claim type
                        var nid = new ClaimsIdentity(
                                    id.AuthenticationType,
                                    Constants.ClaimTypes.GivenName,
                                    Constants.ClaimTypes.Role);

                        nid.AddClaim(givenName);
                        nid.AddClaim(familyName);
                        nid.AddClaim(sub);
                        nid.AddClaims(roles);

                        // add some other app specific claim (just for example)
                        nid.AddClaim(new Claim("app_specific", "some data"));

                        //on logging out we may wish to rediect the user some where.
                        //Client has to prove identity at logout endpoint to ensure we redirect ot correct url (an not spam or phishing site)
                        // Ican;t quite see the use case where this validation is necessary but ho hum...
                        //This is done by sending the initial identity token we received during authentication process.
                        //The following line stops this being completely discarded by claims transformation logic:
                        //keep id_token for logout (id-token is retained in its JWT format)
                        nid.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));

                        n.AuthenticationTicket = new AuthenticationTicket(
                          nid,
                          n.AuthenticationTicket.Properties);
                        return Task.FromResult(0);
                    },

                    
                    //Invoked to manipulate redirects to the identity provider for SignIn, SignOut, or Challenge.
                    RedirectToIdentityProvider = n=>
                    {
                        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest) {
                            var idTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token");
                            if (idTokenHint != null) {
                                n.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                            }
                        }
                        return Task.FromResult(0);
                    }
                }
            });
        }
        

        X509Certificate2 LoadCertificate()
        {
            return new X509Certificate2(
                string.Format(@"{0}\idsrv3test.pfx", AppDomain.CurrentDomain.BaseDirectory), "idsrv3test");
        }
    }
}