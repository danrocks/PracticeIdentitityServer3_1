using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using Thinktecture.IdentityModel.Mvc;

namespace PracticeIdentitityServer3_1.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        [Authorize]
        public ActionResult About()
        {
            //ViewBag.Message = "Your application description page.";
            //return View();
            return View((User as ClaimsPrincipal).Claims);
        }



        /// <summary>
        /// MVC has built in [Authorize]. This could be used to annotate
        /// role membership requirements. It is not reccomended - it mixes concerns
        /// i.e.business/controller logic and authorization policy.
        /// Recommendation is to sperate authprization logic away from controller
        /// - cleaner, more testable code.
        /// install-package Thinktecture.IdentityModel.Owin.ResourceAuthorization.Mvc
        /// In this case, annotate action with attribute expressing that executing action
        /// will read ContactDetails resource.
        /// Note the attribute does not express who can read the contacts...
        /// that logic is in a seperate authorization manager who knows which actions, resources
        /// may be accessed by whom - see class AuthorizationManager 
        /// </summary>
        /// <returns></returns>
        [ResourceAuthorize("Read", "ContactDetails")]
        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}