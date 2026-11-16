var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var orders = app.MapGroup("/orders")
    .RequireAuthorization();
orders.MapGet("/{id}", (int id) => Results.Ok());

var admin = app.MapGroup("/admin");
admin.RequireAuthorization();
admin.MapDelete("/users/{id}", (int id) => Results.NoContent());

var pub = app.MapGroup("/public");
pub.MapGet("/ping", () => "pong");

app.Run();
