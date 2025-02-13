using BookwormsOnline_Trial4.Middleware;
using BookwormsOnline_Trial4.Models;
using BookwormsOnline_Trial4.Models.DbContext;
using BookwormsOnline_Trial4.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// IMPLEMENT THE SESSION STUFF
builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromSeconds(30);
});


// ADD THE DBCONTEXT AND IDENTITY, USE APPLICATION USER
builder.Services.AddDbContext<AuthDbContext>();
builder.Services.AddIdentity<ApplicationUser, IdentityRole>().AddEntityFrameworkStores<AuthDbContext>();

// FORCE THE USER TO GO TO LOGIN PAGE IF NOT LOGGED IN
builder.Services.ConfigureApplicationCookie(Config =>
{
    Config.LoginPath = "/Home/Login";
});

// ADD CAPTCHA SERVICE
builder.Services.AddHttpClient<CaptchaService>();
builder.Services.AddScoped<CaptchaService>();

// TO ENCRYPT & DECRYPT CREDIT CARD USING SERVICE
builder.Services.AddDataProtection();
builder.Services.AddScoped<EncryptionService>();


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();



// SESSION STUFF
app.UseSession();

// USE MIDDLEWARE FOR BROWSER AUTO LOGOUT
app.UseMiddleware<SessionValidationMiddleware>();


// FOR CUSTOM ERROR PAGES
app.UseExceptionHandler("/error/500"); 
app.UseStatusCodePagesWithRedirects("/error/{0}"); 

app.UseRouting();


// FOR THE DBCONTEXT, ADD AUTHENTICATION
app.UseAuthentication();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();