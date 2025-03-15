using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

var auth_scheme1 = "cookie-auth1";
var auth_scheme2 = "cookie-auth2";

builder.Services.AddAuthentication(auth_scheme1)
    .AddCookie(auth_scheme1)
    .AddCookie(auth_scheme2);

builder.Services.AddAuthorization(builder => {
    builder.AddPolicy("Admin", pb => {
        pb.RequireAuthenticatedUser()
            .AddAuthenticationSchemes(auth_scheme1)
            .RequireRole("admin");
            });
    builder.AddPolicy("Master", pb => {
        pb.RequireAuthenticatedUser()
            .AddAuthenticationSchemes(auth_scheme2)
            .RequireRole("master");
            });
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

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
app.MapGet("/profile", async (HttpContext ctx) =>
{
    var result1 = await ctx.AuthenticateAsync(auth_scheme1);
    var result2 = await ctx.AuthenticateAsync(auth_scheme2);
    
    if (!result1.Succeeded && !result2.Succeeded)
    {
        return "Not authenticated with any scheme";
    }
    
    var response = new System.Text.StringBuilder();
    
    if (result1.Succeeded)
    {
        response.AppendLine($"Auth1: User={result1.Principal.Identity.Name}, Role={result1.Principal.FindFirst(ClaimTypes.Role)?.Value}");
    }
    
    if (result2.Succeeded)
    {
        response.AppendLine($"Auth2: User={result2.Principal.Identity.Name}, Role={result2.Principal.FindFirst(ClaimTypes.Role)?.Value}");
    }
    
    return response.ToString().TrimEnd();
});

// Simplified route handlers
app.MapGet("/admin", () => "Admin Page").RequireAuthorization("Admin");
app.MapGet("/master", () => "Master Page").RequireAuthorization("Master");

app.MapGet("/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(auth_scheme1);
    await ctx.SignOutAsync(auth_scheme2);
    return "Logged out";
});

app.Run();