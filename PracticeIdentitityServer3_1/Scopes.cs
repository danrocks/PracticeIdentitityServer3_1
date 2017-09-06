using IdentityServer3.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace PracticeIdentitityServer3_1
{
    public static class Scopes
    {
        public static IEnumerable<Scope> Get()
        {
            List <Scope> scopes = new List<Scope> {
            StandardScopes.OpenId,
            StandardScopes.Profile,
            StandardScopes.Email,
            StandardScopes.Roles,
            StandardScopes.OfflineAccess
        };
            scopes.Add(new Scope
            {
                Enabled = true,
                Name = "roles",
                Type = ScopeType.Identity,
                Claims = new List<ScopeClaim>
                {
                    new ScopeClaim("role")
                }
            });

            scopes.AddRange(StandardScopes.All);

            return scopes;
        }
    }
}