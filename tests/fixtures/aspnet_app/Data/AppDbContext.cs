using Microsoft.EntityFrameworkCore;

namespace Shop.Data;

public class Product { public int Id { get; set; } public string Name { get; set; } }

public class AppDbContext : DbContext
{
    public DbSet<Product> Products { get; set; }
}
