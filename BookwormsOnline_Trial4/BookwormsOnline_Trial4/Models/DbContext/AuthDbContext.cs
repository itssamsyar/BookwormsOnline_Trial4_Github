using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace BookwormsOnline_Trial4.Models.DbContext
{
    public class AuthDbContext : IdentityDbContext<ApplicationUser>
    {
        
        private readonly IConfiguration _configuration;

        public AuthDbContext(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        
        public DbSet<AuditLog> AuditLogs { get; set; } // ✅ Add Audit Logs table

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            string connectionString = _configuration.GetConnectionString("AuthConnectionString");
            optionsBuilder.UseMySQL(connectionString);
        }
    }
}

