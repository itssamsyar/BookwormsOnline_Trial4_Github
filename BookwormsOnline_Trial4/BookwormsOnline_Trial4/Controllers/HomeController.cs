using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using BookwormsOnline_Trial4.Models;
using Microsoft.AspNetCore.Identity;
using BookwormsOnline_Trial4.Models.ViewModels;
using BookwormsOnline_Trial4.Services;

namespace BookwormsOnline_Trial4.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    
    // For my Register
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    
    
    // For the Google ReCAPTCHA V3
    private readonly CaptchaService _captchaService;

    public HomeController(ILogger<HomeController> logger, UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, CaptchaService captchaService)
    {
        _logger = logger;
        _userManager = userManager;
        _signInManager = signInManager;
        _captchaService = captchaService;
        
    }
    
    
    // ALL MY VIEWS
    
    
    // Loads the /Home/Register.cshtml
    public IActionResult Register()
    {
        return View();
    }
    
    // Loads the /Home/Login.cshtml
    public IActionResult Login()
    {
        return View();
    }
    
    // Loads the /Home/Home.cshtml (logged in view)
    public IActionResult Home()
    {
        return View();
    }
    
    // Loads the /Home/Index.cshtml
    public IActionResult Index()
    {
        return View();
    }

    // Loads the /Home/Privacy.cshtml
    public IActionResult Privacy()
    {
        return View();
    }
    
    // Loads the Error View
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    // ALL MY ACTION METHODS
    
    [HttpPost]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        // Log received token for debugging
        Console.WriteLine("Received reCAPTCHA Token: " + model.gRecaptchaResponse);

        // Validate reCAPTCHA first
        bool isCaptchaValid = await _captchaService.ValidateCaptchaAsync(model.gRecaptchaResponse);
        Console.WriteLine("✅ Is Captcha Valid?: " + isCaptchaValid);

        if (!isCaptchaValid)
        {
            Console.WriteLine("❌ reCAPTCHA Validation Failed");
            ModelState.AddModelError("", "Invalid Captcha, please try again.");
            return View(model);
        }

        Console.WriteLine("✅ reCAPTCHA Passed, Continuing Registration");
        

        // Validate other form fields
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        // Create a new user object from IdentityUser
        var user = new IdentityUser
        {
            UserName = model.Email,
            Email = model.Email
        };

        // Add the new user to the database, in the table, AspNetUser
        var result = await _userManager.CreateAsync(user, model.Password);

        if (result.Succeeded)
        {
            await _signInManager.SignInAsync(user, false);
            return RedirectToAction("Home", "Home"); // Redirect after successful registration
        }

        // Handle registration errors
        foreach (var error in result.Errors)
        {
            ModelState.AddModelError("", error.Description);
        }

        return View(model);
    }
    
    // Action Method for Login Button
    
   
    
    // Action Method for Logout Button
    
    
    
    
    
    
    
    
    
    
    
    
    
    

 

    
}