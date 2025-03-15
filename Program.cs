
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Add the authentication services 
// provide the authentication scheme name
// and the cookie name
// this is provided by Microsoft.AspNetCore.Authentication.Cookies
builder.Services.AddAuthentication("cookie-auth")
    .AddCookie("cookie-auth", options =>
    {
        options.Cookie.Name = "auth";
    });


var app = builder.Build();

// Add the authentication middleware
// this middleware will recognize the authentication session
// and populate the HttpContext.User property
// provided by Microsoft.AspNetCore.Authentication
app.UseAuthentication();

app.MapGet("/admin-only", (HttpContext ctx) =>
{
    // check if the user is authenticated
    if (!ctx.User.Identities.Any(identity => identity.AuthenticationType == "cookie-auth"))
    {
        ctx.Response.StatusCode = 401;
        return "You are not authenticated";
    }
    // check if the user has the role of Admin
    if (!ctx.User?.FindFirst("role")?.Value.Equals("Admin") ?? true)
    {
        ctx.Response.StatusCode = 403;
        return "You are not authorized";
    }
    return "Admin Page";
});

app.MapGet("/login", async (HttpContext ctx) =>

{
    // create a list of claims
    var claims = new List<Claim>();

    // Add the claim to the list
    claims.Add(new Claim("user", "abir"));
    // add the role
    claims.Add(new Claim("role", "Admin"));
    // Create a ClaimsIdentity and add it to the HttpContext.User
    var identity = new ClaimsIdentity(claims, "cookie-auth");
    // Add the ClaimsPrincipal to the HttpContext
    var user = new ClaimsPrincipal(identity);
    // creating an authentication session
    await ctx.SignInAsync("cookie-auth", user);

    return "Login Page";
});


app.MapGet("/profile", (HttpContext ctx) =>
{       
    // recognizing the authentication session
    var username = ctx.User?.FindFirst("user")?.Value ?? "Anonymous";
    var role = ctx.User?.FindFirst("role")?.Value ?? "User";
    return $"Welcome {username} you are a {role}";
    
});
app.Run();