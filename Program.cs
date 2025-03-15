using Auth.middlewares;
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

// Add the middleware to the pipeline
app.UseMiddleware<AuthMiddleware>();

app.MapGet("/login", (AuthService auth) =>

{
    // creating an authentication session
    auth.SignIn();

    return "Login Page";
});

app.MapGet("/profile", (HttpContext ctx) =>
{       
    // recognizing the authentication session
    var username = ctx.User?.FindFirst("user")?.Value ?? "Anonymous";
    return $"Welcome {username}";
});
app.Run();