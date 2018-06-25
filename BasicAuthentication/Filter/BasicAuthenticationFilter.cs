using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace BasicAuthentication.Filter
{
    public class BasicAuthenticationFilter:AuthorizationFilterAttribute
    {
        public override void OnAuthorization(HttpActionContext actionContext)
        {
            //base.OnAuthorization(actionContext);
            if(actionContext.Request.Headers.Authorization == null)
            {
                actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                //actionContext.Response.Content =new HttpResponseMessage( HttpStatusCode.Unauthorized "123456789";
            }
            else
            {
                string authenticationToken = actionContext.Request.Headers.Authorization.Parameter;
                if (authenticationToken != null)
                {

                    var auth = Encoding.UTF8.GetString(Convert.FromBase64String(authenticationToken));
                    string[] identity = auth.Split(':');
                    var userName = identity[0];
                    var password = identity[1];

                    if (userName == "borothana.doul@gmail.com" && password == "12345678")
                    {
                        Thread.CurrentPrincipal = new GenericPrincipal(new GenericIdentity(userName), new string[] { "admin" });
                        return;
                    }                    
                }
                actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
            }
        }
    }
}