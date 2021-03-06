﻿using IdentityServer3.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

//https://identityserver.github.io/Documentation/docsv2/overview/mvcGettingStarted.html
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
                    // a particular site e.g. the homepage on logging out.
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

                    //AllowAccessToAllScopes = true// at this stage, all scopes are available
                    AllowedScopes = new List<string>
                    {
                        "openid",
                        "profile",
                        "roles",
                        "sampleApi"
                    }
                },
                new Client {
                    //When calling WebApi, we could use client credentials(eg service accout) or by delegating users identity.
                    // Here we are using client credentials.
                    // For security IdentityServer3 only allows one flow per client...since existing MVC client (above) already uses
                    // implcit flow, we need to create this client for service to service communication
                    ClientName = "MVC Client (service communication)",
                    ClientId= "mvc_service",
                    Flow = Flows.ClientCredentials,

                    ClientSecrets = new List<Secret> {
                            new Secret("secret".Sha256())
                    },
                    // Lock down the scopes that can be accessed by the various clients.
                    // Nb You could list anything here = Scope "cripes" does not exist.
                    // Made-up scopes appear to bne sliently stripped though.
                    AllowedScopes = new List<string> {
                            "sampleApi","cripes"
                    }
                }          
            };
        }
    }
}