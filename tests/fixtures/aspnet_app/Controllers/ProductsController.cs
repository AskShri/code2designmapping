using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Shop.Data;

namespace Shop.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ProductsController : ControllerBase
{
    private readonly AppDbContext _db;

    public ProductsController(AppDbContext db) { _db = db; }

    [HttpGet("{id}")]
    public IActionResult Get(int id) => Ok(_db.Products.Find(id));

    [HttpGet]
    [AllowAnonymous]
    public IActionResult List() => Ok(_db.Products.ToList());
}
