using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

var auth_scheme1 = "cookie-auth1";
var auth_scheme2 = "cookie-auth2";

// Set up both authentication schemes without a default
builder.Services.AddAuthentication()
    .AddCookie(auth_scheme1)
    .AddCookie(auth_scheme2);

var app = builder.Build();

app.UseAuthentication();

app.MapGet("/login/{user?}/{role?}", async (HttpContext ctx, string? user, string? role) =>
{
    string userName = user ?? "Anonymous";
    string roleN = role ?? "user";
    string scheme = roleN == "master" ? auth_scheme2 : auth_scheme1;

    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.Name, userName),
        new Claim(ClaimTypes.Role, roleN)
    };

    var identity = new ClaimsIdentity(claims, scheme);
    Console.WriteLine($"Signing in: User={userName}, Role={roleN}, Scheme={scheme}");
    await ctx.SignInAsync(scheme, new ClaimsPrincipal(identity));
    return $"Login Page - Logged in as {userName} with role {roleN} using scheme {scheme}";
});

app.MapGet("/profile", async (HttpContext ctx) =>
{
    // Explicitly authenticate using both schemes
    var result1 = await ctx.AuthenticateAsync(auth_scheme1);
    var result2 = await ctx.AuthenticateAsync(auth_scheme2);
    
    string userInfo = "Not authenticated";
    
    if (result1.Succeeded)
    {
        userInfo = $"Auth1: User: {result1.Principal.Identity.Name}, Role: {result1.Principal.FindFirst(ClaimTypes.Role)?.Value}";
    }
    
    if (result2.Succeeded)
    {
        userInfo += $"\nAuth2: User: {result2.Principal.Identity.Name}, Role: {result2.Principal.FindFirst(ClaimTypes.Role)?.Value}";
    }
    
    return userInfo;
});

app.MapGet("/admin", async (HttpContext ctx) =>
{
    var result = await ctx.AuthenticateAsync(auth_scheme1);
    
    if (!result.Succeeded)
    {   
        ctx.Response.StatusCode = 401;
        return "Unauthorized";
    }
    
    if (!result.Principal.IsInRole("admin"))
    {
        ctx.Response.StatusCode = 403;
        return "Forbidden";
    }
    
    return "Admin Page";
});

app.MapGet("/master", async (HttpContext ctx) =>
{   
    var result = await ctx.AuthenticateAsync(auth_scheme2);
    
    if (!result.Succeeded)
    {   
        ctx.Response.StatusCode = 401;
        return "Unauthorized";
    }
    
    if (!result.Principal.IsInRole("master"))
    {
        ctx.Response.StatusCode = 403;
        return "Forbidden";
    }
    
    return "Master Page";
});

app.MapGet("/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(auth_scheme1);
    await ctx.SignOutAsync(auth_scheme2);
    return "Logged out";
});

app.Run();