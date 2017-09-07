using IdentityServer3.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace PracticeIdentitityServer3_1
{
    public static class Clients
    {
        public static IEnumerable<Client> Get()
        {
            return new[]
            {
            new Client
            {
                Enabled = true,
                ClientName = "MVC Client",
                ClientId = "mvc",
                Flow = Flows.Implicit,

                RedirectUris = new List<string>
                {
                    "https://localhost:44370/"
                },

                //the following is set-up inorder that a user will be redirected to 
                // a particular site .e.g the homepage on logging out.
                // To make this redirection work, further enhancments must also be made on the 
                // handling of notifications in th OpenIdConnectAuthenticationOptions (se startup.cs).
                // The default IdentityServer3 implementation simply provides a link to the login page on 
                // it's default logout page.
                // As an alternative to all this, on the IdentityServerOptions you find an AuthenticationOptions object. 
                // This has a property called EnablePostSignOutAutoRedirect. 
                // Setting this to true will automatically redirect back to the client after logout.
                PostLogoutRedirectUris = new List<string>
                {
                    "https://localhost:44370/"
                },

                AllowAccessToAllScopes = true
            }
            // at this stage, all scopes are available
        };
        }
    }
}