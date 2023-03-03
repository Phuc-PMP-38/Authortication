using Authortication.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Authortication.Data
{
    public class AppDataContext : IdentityDbContext<ApplicationUser>
    {
        public AppDataContext(DbContextOptions<AppDataContext> options) : base(options)
        {

        }
        public DbSet<UserRefeshToken> UserRefeshTokens { get; set; }
    }
}
