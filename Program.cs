using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDataProtection();

var app = builder.Build();


app.MapGet("/login", (HttpContext ctx, IDataProtectionProvider idp) =>
{
    // creating an authentication session
    // create protector <name> - auth (scenario/usecase)
    var protector = idp.CreateProtector("auth");
    
    // the string to protect
    var payload = "user:abir";

    // create protected payload
    var protectedPayload = protector.Protect(payload);

    ctx.Response.Headers["set-cookie"]= $"auth={protectedPayload}";

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