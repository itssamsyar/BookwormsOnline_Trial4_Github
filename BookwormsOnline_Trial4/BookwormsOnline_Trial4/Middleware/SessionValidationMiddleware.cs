using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using System.Linq;
using System.Threading.Tasks;
using BookwormsOnline_Trial4.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;

namespace BookwormsOnline_Trial4.Middleware
{
    public class SessionValidationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IServiceScopeFactory _scopeFactory; // ✅ Use Scope Factory

        public SessionValidationMiddleware(RequestDelegate next, IServiceScopeFactory scopeFactory)
        {
            _next = next;
            _scopeFactory = scopeFactory;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            using (var scope = _scopeFactory.CreateScope())  // ✅ Create a scoped service provider
            {
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

                string userId = context.Session.GetString("UserId");
                string sessionToken = context.Session.GetString("AuthToken");

                if (!string.IsNullOrEmpty(userId) && !string.IsNullOrEmpty(sessionToken))
                {
                    var user = await userManager.Users.FirstOrDefaultAsync(u => u.Id == userId);
                    if (user == null || user.AuthToken != sessionToken)
                    {
                        context.Session.Clear();
                        context.Response.Cookies.Delete("AuthToken");
                        await context.SignOutAsync(IdentityConstants.ApplicationScheme);

                        context.Response.Redirect("/Home/Login");
                        return;
                    }
                }
            }

            await _next(context);
        }
    }
}
