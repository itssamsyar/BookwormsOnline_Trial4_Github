using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using BookwormsOnline_Trial4.Models;
using Microsoft.AspNetCore.Identity;
using BookwormsOnline_Trial4.Models.ViewModels;
using BookwormsOnline_Trial4.Services;
using Microsoft.AspNetCore.Authorization;

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
    [HttpGet]
    public IActionResult Login()
    {
        return View(new LoginViewModel()); // Ensure a fresh instance is passed
    }

    
    // Loads the /Home/Home.cshtml (logged in view)
    [Authorize]
    public IActionResult Home()
    {
        if (!User.Identity.IsAuthenticated)
        {
            Console.WriteLine("❌ User is NOT authenticated!");
        }
        else
        {
            Console.WriteLine($"✅ User is authenticated: {User.Identity.Name}");
        }

        return View();
    }
    
    
    // Loads the /Home/Index.cshtml
    public IActionResult Index()
    {
        return RedirectToAction("Login", "Home");
    }

    
    // Load the /Home/Logout.cshtml
    public IActionResult Logout()
    {
        return View();
    }

    // Loads the /Home/Privacy.cshtml
    [Authorize]
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
    
    
    // Action Method for Register Button
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
    [HttpPost]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        
        Console.WriteLine("🔍 Login POST method hit!");
        
        if (!ModelState.IsValid)
        {
            Console.WriteLine("❌ ModelState is Invalid!");
            
            foreach (var error in ModelState)
            {
                foreach (var subError in error.Value.Errors)
                {
                    Console.WriteLine($"❌ Validation Error for {error.Key}: {subError.ErrorMessage}");
                }
            }
            
        

            return View(model);
        }
        
        Console.WriteLine("The stuff is valid!");

        var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);

        if (result.Succeeded)
        {
            Console.WriteLine($"✅ Login Successful! User: {model.Email}");
            return RedirectToAction("Home", "Home");
        }

        ModelState.AddModelError("", "Username or Password incorrect");

        return View(model);
    }
    
   
    
    // Action Method for Confirm Logout Button
    [HttpPost]
    public async Task<IActionResult> ConfirmLogout()
    {
        await _signInManager.SignOutAsync();
        return RedirectToAction("Login");
    }

    
    // Action Method for CancelLogoutButton
    [HttpPost]
    public IActionResult CancelLogout()
    {
        return RedirectToAction("Home", "Home");
    }
    
    
    
    
    
    
    
    
    
    
    
    
    
    

 

    
}