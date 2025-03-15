using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Linq;
using System.Text;

public class CustomAuthorizationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly Dictionary<string, AuthRequirement> _routeRequirements;
    private readonly string[] _authSchemes;
    
    public CustomAuthorizationMiddleware(RequestDelegate next, string[] authSchemes)
    {
        _next = next;
        _authSchemes = authSchemes;
        
        // Define route requirements
        _routeRequirements = new Dictionary<string, AuthRequirement>
        {
            // Define which routes require which authentication schemes and roles
            { "/admin", new AuthRequirement(_authSchemes[0], "admin") },
            { "/master", new AuthRequirement(_authSchemes[1], "master") },
            // Special handling for profile - it accepts any authentication scheme
            { "/profile", new AuthRequirement(null, null, true) }
        };
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value;
        
        // Check if the current path has any authorization requirements
        if (_routeRequirements.TryGetValue(path, out var requirement))
        {
            if (requirement.IsProfileRoute)
            {
                // For profile route, we'll try all schemes and merge information
                await HandleProfileRoute(context);
                return;
            }
            
            // For specific routes, authenticate using the required scheme
            var authResult = await context.AuthenticateAsync(requirement.Scheme);
            
            if (!authResult.Succeeded)
            {
                // Not authenticated with the required scheme
                context.Response.StatusCode = 401; // Unauthorized
                await context.Response.WriteAsync("Unauthorized");
                return;
            }
            
            // Check role if required
            if (!string.IsNullOrEmpty(requirement.RequiredRole) && 
                !authResult.Principal.IsInRole(requirement.RequiredRole))
            {
                context.Response.StatusCode = 403; // Forbidden
                await context.Response.WriteAsync("Forbidden");
                return;
            }
            
            // Override the context's user with the authenticated principal
            context.User = authResult.Principal;
        }
        
        // Continue to the next middleware
        await _next(context);
    }
    
    private async Task HandleProfileRoute(HttpContext context)
    {
        var authenticatedSchemes = new List<string>();
        var userInfo = new StringBuilder();
        bool isAuthenticated = false;
        
        // Try each authentication scheme
        foreach (var scheme in _authSchemes)
        {
            var result = await context.AuthenticateAsync(scheme);
            if (result.Succeeded)
            {
                isAuthenticated = true;
                authenticatedSchemes.Add(scheme);
                
                var userName = result.Principal.Identity.Name;
                var role = result.Principal.FindFirst(ClaimTypes.Role)?.Value;
                
                userInfo.AppendLine($"Scheme: {scheme}, User: {userName}, Role: {role}");
                
                // Set the user principal from the first successful authentication
                if (context.User?.Identity?.IsAuthenticated != true)
                {
                    context.User = result.Principal;
                }
            }
        }
        
        if (!isAuthenticated)
        {
            context.Response.StatusCode = 401; // Unauthorized
            await context.Response.WriteAsync("Not logged in with any scheme");
            return;
        }
        
        // Set the response content
        context.Response.ContentType = "text/plain";
        await context.Response.WriteAsync(userInfo.ToString());
    }
}

// Class to hold authentication requirements for a route
public class AuthRequirement
{
    public string Scheme { get; }
    public string RequiredRole { get; }
    public bool IsProfileRoute { get; }
    
    public AuthRequirement(string scheme, string requiredRole = null, bool isProfileRoute = false)
    {
        Scheme = scheme;
        RequiredRole = requiredRole;
        IsProfileRoute = isProfileRoute;
    }
}

// Extension method to add the custom middleware to the ASP.NET Core pipeline
public static class CustomAuthorizationMiddlewareExtensions
{
    public static IApplicationBuilder UseCustomAuthorization(
        this IApplicationBuilder builder,
        params string[] authSchemes)
    {
        return builder.UseMiddleware<CustomAuthorizationMiddleware>(
            new object[] { authSchemes });
    }
}