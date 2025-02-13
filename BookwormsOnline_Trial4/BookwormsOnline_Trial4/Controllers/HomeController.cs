using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using BookwormsOnline_Trial4.Models;
using BookwormsOnline_Trial4.Models.DbContext;
using Microsoft.AspNetCore.Identity;
using BookwormsOnline_Trial4.Models.ViewModels;
using BookwormsOnline_Trial4.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;

namespace BookwormsOnline_Trial4.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    
    // For my Register
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    
    // For the Google ReCAPTCHA V3
    private readonly CaptchaService _captchaService;
    
    // For Encrypting CreditCard
    private readonly IDataProtector _protector;
    
    // For Session Cookies
    private readonly IHttpContextAccessor contxt;
    
    // For the Database
    private readonly AuthDbContext _context;

    public HomeController(ILogger<HomeController> logger, 
        UserManager<ApplicationUser> userManager, 
        SignInManager<ApplicationUser> signInManager, 
        CaptchaService captchaService, 
        IDataProtectionProvider provider,
        IHttpContextAccessor httpContextAccessor,
        AuthDbContext context)
    {
        _logger = logger;
        _userManager = userManager;
        _signInManager = signInManager;
        _captchaService = captchaService;
        _protector = provider.CreateProtector("CreditCardProtection");
        contxt = httpContextAccessor;
        _context = context;
        
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
    public async Task<IActionResult> Home()
    {
        string userId = HttpContext.Session.GetString("UserId");
        string sessionAuthToken = HttpContext.Session.GetString("AuthToken");
        string cookieAuthToken = Request.Cookies["AuthToken"];

        // ✅ Validate Session & Cookie Authentication
        if (string.IsNullOrEmpty(userId) || 
            string.IsNullOrEmpty(sessionAuthToken) || 
            string.IsNullOrEmpty(cookieAuthToken) ||
            sessionAuthToken != cookieAuthToken)
        {
            Console.WriteLine("❌ Invalid or expired session. Redirecting to login...");
            return RedirectToAction("Login", "Home");
        }

        // ✅ Securely retrieve user data using parameterized query
        var user = await _context.Users
            .Where(u => u.Id == userId)
            .Select(u => new 
            {
                u.FirstName,
                u.LastName,
                u.Email,
                u.PhoneNumber,
                u.BillingAddress,
                u.ShippingAddress,
                u.PhotoPath
            })
            .FirstOrDefaultAsync();

        if (user == null)
        {
            Console.WriteLine("❌ User not found in database!");
            return RedirectToAction("Login", "Home");
        }

        ViewBag.User = user; // Pass user details to the view
        ViewBag.IsLoggedIn = true;
        ViewBag.Message = $"Welcome, {user.FirstName} {user.LastName}!";

        Console.WriteLine($"✅ Successfully loaded Home page for {user.Email}");

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
        
        // File validation for the uploaded photo
        if (model.Photo != null)
        {
            string fileExtension = Path.GetExtension(model.Photo.FileName).ToLower();
            string contentType = model.Photo.ContentType.ToLower();

            Console.WriteLine($"📷 Uploaded File Name: {model.Photo.FileName}");
            Console.WriteLine($"📷 File Extension: {fileExtension}");
            Console.WriteLine($"📷 MIME Type: {contentType}");

            // Allowed extensions
            var allowedExtensions = new HashSet<string> { ".jpg", ".jpeg" };

            // Validate file extension (case insensitive)
            if (!allowedExtensions.Contains(fileExtension))
            {
                Console.WriteLine("❌ File extension not allowed!");
                ModelState.AddModelError("Photo", "Only .jpg or .jpeg files are allowed.");
                return View(model);
            }

            // Validate MIME type (ensures the file is actually an image)
            var allowedMimeTypes = new HashSet<string> { "image/jpeg", "image/jpg" };
            if (!allowedMimeTypes.Contains(contentType))
            {
                Console.WriteLine("❌ Invalid file type!");
                ModelState.AddModelError("Photo", "Invalid file type. Only JPEG images are allowed.");
                return View(model);
            }

            Console.WriteLine("✅ File is a valid JPEG.");
        }
        else
        {
            Console.WriteLine("⚠ No profile photo uploaded.");
        }

        
        
        
        

        // Validate other form fields
        if (!ModelState.IsValid)
        {
            Console.WriteLine("❌ Model validation failed:");
            foreach (var modelState in ModelState)
            {
                foreach (var error in modelState.Value.Errors)
                {
                    Console.WriteLine($"⚠ Field: {modelState.Key}, Error: {error.ErrorMessage}");
                }
            }
            return View(model);
        }
        
        
        Console.WriteLine("✅ Model validation passed");
        Console.WriteLine("🛠 Creating new ApplicationUser object...");
        
        // Create a new user object from ApplicationUser
        var user = new ApplicationUser(_protector)
        {
            UserName = model.Email,  // Identity requires a unique username, using email as default
            Email = model.Email,
            PhoneNumber = model.PhoneNumber,
            FirstName = model.FirstName,
            LastName = model.LastName,
            BillingAddress = model.BillingAddress,
            ShippingAddress = model.ShippingAddress
        };
        
        Console.WriteLine($"✅ Created user object: {user.Email}");

        
        // Encrypt and store credit card number
        Console.WriteLine("🔒 Encrypting credit card...");
        user.SetEncryptedCreditCard(model.CreditCardNumber);


        Console.WriteLine("✅ Credit card encrypted successfully");
        
        // Define uploads directory
        var uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/uploads");

        // Ensure directory exists
        if (!Directory.Exists(uploadsFolder))
        {
            Directory.CreateDirectory(uploadsFolder);
            Console.WriteLine("📂 Created 'uploads' folder in wwwroot");
        }

        // Handle profile photo upload (save file and store path)
        if (model.Photo != null && model.Photo.Length > 0)
        {
            Console.WriteLine("📷 Processing profile photo...");

            // Generate a unique filename to prevent overwrites
            var uniqueFileName = $"{Guid.NewGuid()}{Path.GetExtension(model.Photo.FileName)}";
            var filePath = Path.Combine(uploadsFolder, uniqueFileName);

            // Save file to server
            using (var fileStream = new FileStream(filePath, FileMode.Create))
            {
                await model.Photo.CopyToAsync(fileStream);
            }

            // Store relative file path in the database
            user.PhotoPath = $"/uploads/{uniqueFileName}";
            Console.WriteLine($"✅ Profile photo saved at: {user.PhotoPath}");
        }
        else
        {
            Console.WriteLine("⚠ No profile photo uploaded.");
        }
        
        
        
        
        
        
        
        
        // Check if the email already exists
        var existingUser = await _userManager.FindByEmailAsync(model.Email);
        if (existingUser != null)
        {
            Console.WriteLine("❌ Registration failed: Email already exists.");
            ModelState.AddModelError("Email", "An account with this email already exists.");
            return View(model);
        }

        Console.WriteLine("✅ Email is unique, proceeding with registration...");
        
        
        
        
        
        
        


        // Add the new user to the AspNetUser, salt hash the password
        var result = await _userManager.CreateAsync(user, model.Password);

        if (result.Succeeded)
        {
            Console.WriteLine("🎉 User created successfully!");
            return RedirectToAction("Login", "Home"); // Redirect after successful registration
        }

        // Handle registration errors
        Console.WriteLine("❌ User creation failed:");
        foreach (var error in result.Errors)
        {
            Console.WriteLine($"⚠ Error: {error.Code} - {error.Description}");
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
        
        // ✅ Query user using parameterized query (prevents SQL injection)
        var user = await _userManager.Users
            .Where(u => u.Email == model.Email)
            .FirstOrDefaultAsync();
        
        if (user == null)
        {
            Console.WriteLine("❌ User not found!");
            ModelState.AddModelError("", "Username or Password incorrect");
            return View(model);
        }

        var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);

        if (result.Succeeded)
        {
            Console.WriteLine($"✅ Login Successful! User: {user.Email}");

            // ✅ Store session variables
            HttpContext.Session.SetString("LoggedIn", user.Email);
            HttpContext.Session.SetString("UserId", user.Id);

            string guid = Guid.NewGuid().ToString();
            HttpContext.Session.SetString("AuthToken", guid);

            Response.Cookies.Append("AuthToken", guid, new CookieOptions
            {
                HttpOnly = true, // Security best practice
                Secure = true, // Requires HTTPS
                SameSite = SameSiteMode.Strict, // Helps prevent CSRF
                Expires = DateTime.UtcNow.AddHours(1) // Expiration time
            });

            return RedirectToAction("Home", "Home");
        }

        ModelState.AddModelError("", "Username or Password incorrect");
        return View(model);
    }
    
    
    // Action Method for Confirm Logout Button
    [HttpPost]
    public async Task<IActionResult> ConfirmLogout()
    {
        // ✅ Clear session data
        HttpContext.Session.Clear();

        // ✅ Delete session cookie
        if (Request.Cookies.ContainsKey("AuthToken"))
        {
            Response.Cookies.Delete("AuthToken");
        }

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