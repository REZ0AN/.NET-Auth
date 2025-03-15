using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

var auth_scheme1 = "cookie-auth1";
var auth_scheme2 = "cookie-auth2";

builder.Services.AddAuthentication()
    .AddCookie(auth_scheme1)
    .AddCookie(auth_scheme2);

var app = builder.Build();

app.UseAuthentication();
// Pass the authentication schemes to the middleware
app.UseCustomAuthorization(auth_scheme1, auth_scheme2);

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

// The profile endpoint is now handled directly in the middleware
app.MapGet("/profile", () => "This response will be replaced by the middleware");

// Simplified route handlers
app.MapGet("/admin", () => "Admin Page");
app.MapGet("/master", () => "Master Page");

app.MapGet("/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(auth_scheme1);
    await ctx.SignOutAsync(auth_scheme2);
    return "Logged out";
});

app.Run();