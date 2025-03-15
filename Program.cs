using Auth.services;
using Microsoft.AspNetCore.DataProtection;
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDataProtection();

// adding the custom service to the DI container
// When we create a custom services and need to access the HttpContext,
// we need to inject IHttpContextAccessor to access the HttpContext.    
builder.Services.AddHttpContextAccessor();

// adding the AuthService to the DI container
// AuthService requires IDataProtectionProvider and IHttpContextAccessor
builder.Services.AddScoped<AuthService>();

var app = builder.Build();


app.MapGet("/login", (AuthService auth) =>

{
    // creating an authentication session
    auth.SignIn();

    return "Login Page";
});

app.MapGet("/profile", (HttpContext ctx, IDataProtectionProvider idp) =>
{   
    // recognizing the authentication session
    // create protector <name> - auth (scenario/usecase)
    var protector = idp.CreateProtector("auth");

    // extracting information from cookie
    var authCookie =  ctx.Request.Headers.Cookie.FirstOrDefault(c => c.StartsWith("auth="));
    
    // get the protected payload
    var protectedPayload = authCookie?.Split("=").Last();

    // unprotect the protected payload
    var payload = protector.Unprotect(protectedPayload);

    // split the payload to get the key and value
    var parts = payload?.Split(":");
    var key = parts[0];
    var value = parts[1];

    return $"Welcome {value}";
});
app.Run();