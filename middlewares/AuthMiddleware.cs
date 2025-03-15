using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;

namespace Auth.middlewares
{
    public class AuthMiddleware
    {
        // The RequestDelegate is a delegate that represents
        //  the next middleware in the pipeline.
        private readonly RequestDelegate _next;
        private readonly IDataProtectionProvider _idp;

        public AuthMiddleware(RequestDelegate next, IDataProtectionProvider idp)
        {
            _next = next;
            _idp = idp;
        }

        // The InvokeAsync method is called for each HTTP request
        public async Task InvokeAsync(HttpContext ctx)
        {
            
            // Create a protector for the "auth" scenario
            var protector = _idp.CreateProtector("auth");

            // Extract the auth cookie from the request headers
            var authCookie = ctx.Request.Cookies.FirstOrDefault(c => c.Key.StartsWith("auth"));

            if (authCookie.Key != null)
            {
                // Get the protected payload from the cookie value
                var protectedPayload = authCookie.Value;

                try
                {
                    // Unprotect the payload
                    var payload = protector.Unprotect(protectedPayload);

                    // Split the payload to get key and value (assuming format is "key:value")
                    var parts = payload?.Split(":");
                    if (parts != null && parts.Length == 2)
                    {
                        var key = parts[0];
                        var value = parts[1];
                        
                        // create a list of claims
                        var claims = new List<Claim>();

                        // Add the claim to the list
                        claims.Add(new Claim(key, value));

                        // Create a ClaimsIdentity and add it to the HttpContext.User
                        var identity = new ClaimsIdentity(claims, "CookieAuth");
                        // Add the ClaimsPrincipal to the HttpContext
                        ctx.User = new ClaimsPrincipal(identity);
                    }
                } catch (Exception ex)
                {
                    // Log the exception
                    Console.WriteLine(ex.Message);
                }

            }

                await _next(ctx);
            }

        
    }
}