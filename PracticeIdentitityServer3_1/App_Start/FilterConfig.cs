using System.Web;
using System.Web.Mvc;
using Thinktecture.IdentityModel.Mvc;

namespace PracticeIdentitityServer3_1
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleForbiddenAttribute());
            filters.Add(new HandleErrorAttribute());
            
        }
    }
}
