using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using Thinktecture.IdentityModel.Owin.ResourceAuthorization;

namespace PracticeIdentitityServer3_1
{
    /// <summary>
    /// Provides authorization service for controller actions
    /// annotated with ResourceAuthorize attribue
    /// </summary>
    public class AuthorizationManager : ResourceAuthorizationManager
    {
        /// <summary>
        /// This will be rub just prior to a controller action being invoked...
        /// It is the authorizor for an action being invoked.
        /// It authorises based on the claims the current user already has.
        /// How do the claims get from the JWT to the ClaimsPrincipal - not sure yet.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task<bool> CheckAccessAsync(ResourceAuthorizationContext context)
        {
            switch (context.Resource.First().Value)
            {
                case "ContactDetails":
                    return AuthorizeContactDetails(context);
                default:
                    return Nok();
            }
        }

        private Task<bool> AuthorizeContactDetails(ResourceAuthorizationContext context)
        {
            switch (context.Action.First().Value)
            {
                case "Read":
                    return Eval(context.Principal.HasClaim("role", "Geek"));
                case "Write":
                    return Eval(context.Principal.HasClaim("role", "Operator"));
                default:
                    return Nok();
            }
        }
    }
}