var builder = WebApplication.CreateBuilder(args);


var app = builder.Build();


app.MapGet("/login", (HttpContext ctx) =>
{
    ctx.Response.Headers["set-cookie"]= "auth=user:abir";
    return "Login Page";
});

app.MapGet("/profile", (HttpContext ctx) =>
{
    // extracting information from cookie
    var authCookie =  ctx.Request.Headers.Cookie.FirstOrDefault(c => c.StartsWith("auth="));
    var payload = authCookie?.Split("=").Last();
    var parts = payload?.Split(":");
    var key = parts[0];
    var value = parts[1];

    return $"Welcome {value}";
});
app.Run();