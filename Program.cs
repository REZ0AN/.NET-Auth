var builder = WebApplication.CreateBuilder(args);


var app = builder.Build();


app.MapGet("/login", (HttpContext ctx) =>
{
    ctx.Response.Headers["set-cookie"]= "auth=user:abir";
    return "Login Page";
});

app.MapGet("/profile", () =>
{
    return "Profile Page";
});
app.Run();