using Microsoft.AspNetCore.DataProtection;
namespace Auth.services
{
    public class AuthService
    {
        
        private readonly IDataProtectionProvider _idp;
        private readonly IHttpContextAccessor _httpContextAccessor;

        // Injecting IDataProtectionProvider and IHttpContextAccessor
        // why? to create a protector and to access the HttpContext
        // When we create a custom services and need to access the HttpContext, 
        // we need to inject IHttpContextAccessor to access the HttpContext.   

        public AuthService(IDataProtectionProvider idp, IHttpContextAccessor httpContextAccessor)
        {
            _idp = idp;
            _httpContextAccessor = httpContextAccessor;

        }

        public void SignIn() {

            // create protector <name> - auth (scenario/usecase)
            var protector = _idp.CreateProtector("auth");
            // the string to protect
            var payload = "user:abir";
            // create protected payload
            var protectedPayload = protector.Protect(payload);
            _httpContextAccessor.HttpContext.Response.Headers["set-cookie"]= $"auth={protectedPayload}";
        }
    }
}