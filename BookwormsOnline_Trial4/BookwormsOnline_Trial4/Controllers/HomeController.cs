using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Web;
using Microsoft.AspNetCore.Mvc;
using BookwormsOnline_Trial4.Models;
using BookwormsOnline_Trial4.Models.DbContext;
using Microsoft.AspNetCore.Identity;
using BookwormsOnline_Trial4.Models.ViewModels;
using BookwormsOnline_Trial4.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.UI.Services;

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
    private readonly EncryptionService _encryptionService;

    // For Session Cookies
    private readonly IHttpContextAccessor contxt;

    // For the Database
    private readonly AuthDbContext _context;

    // For the Email
    private readonly IEmailSender _emailSender;

    public HomeController(ILogger<HomeController> logger,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        CaptchaService captchaService,
        IDataProtectionProvider provider,
        IHttpContextAccessor httpContextAccessor,
        AuthDbContext context,
        EncryptionService encryptionService,
        IEmailSender emailSender)
    {
        _logger = logger;
        _userManager = userManager;
        _signInManager = signInManager;
        _captchaService = captchaService;
        _protector = provider.CreateProtector("CreditCardProtection");
        contxt = httpContextAccessor;
        _context = context;
        _encryptionService = encryptionService;
        _emailSender = emailSender;
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
    public async Task<IActionResult> Home([FromServices] EncryptionService encryptionService)
    {
        // ✅ Prevent caching so that pressing "Back" doesn’t load the old page
        Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
        Response.Headers["Pragma"] = "no-cache";
        Response.Headers["Expires"] = "0";


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

        // ✅ Retrieve full ApplicationUser object instead of using Select()
        var user = await _context.Users
            .OfType<ApplicationUser>() // Ensure Entity Framework correctly casts to ApplicationUser
            .FirstOrDefaultAsync(u => u.Id == userId);


        if (user == null)
        {
            Console.WriteLine("❌ User not found in database!");
            return RedirectToAction("Login", "Home");
        }

        // ✅ Get encrypted credit card from the database
        string decryptedCreditCard = "Not Available";
        try
        {
            if (!string.IsNullOrEmpty(user.EncryptedCreditCard))
            {
                decryptedCreditCard = encryptionService.Decrypt(user.EncryptedCreditCard);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error decrypting credit card: {ex.Message}");
        }

        ViewBag.User = new
        {
            user.FirstName,
            user.LastName,
            user.Email,
            user.PhoneNumber,
            user.BillingAddress,
            user.ShippingAddress,
            user.PhotoPath,
            DecryptedCreditCard = decryptedCreditCard
        };


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


    // Loads the /Home/ChangePassword.cshtml
    [Authorize]
    public IActionResult ChangePassword()
    {
        string userId = HttpContext.Session.GetString("UserId");
        string sessionAuthToken = HttpContext.Session.GetString("AuthToken");
        string cookieAuthToken = Request.Cookies["AuthToken"];

        // ✅ Validate session & cookie authentication
        if (string.IsNullOrEmpty(userId) ||
            string.IsNullOrEmpty(sessionAuthToken) ||
            string.IsNullOrEmpty(cookieAuthToken) ||
            sessionAuthToken != cookieAuthToken)
        {
            Console.WriteLine("❌ Invalid session. Redirecting to login...");
            return RedirectToAction("Login", "Home");
        }

        Console.WriteLine($"✅ Change Password Page Loaded for UserID: {userId}");

        return View();
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


    // Loads the /Home/ForgotPassword.cshtml
    [HttpGet]
    public IActionResult ForgotPassword()
    {
        return View();
    }


    // Loads the /Home/ResetPassword.cshtml
    [HttpGet]
    public IActionResult ResetPassword(string token, string email)
    {
        if (token == null || email == null) return BadRequest("Invalid token.");
        return View(new ResetPasswordViewModel { Token = token, Email = email });
    }

    // Loads the Error View
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }


    // METHOD TO SANITIZE INPUT
    private string SanitizeInput(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return input;
        }

        // Convert <script> into &ltscript&gt to prevent execution
        input = Regex.Replace(input, "<script", "&ltscript", RegexOptions.IgnoreCase);

        // Encode input to prevent XSS attacks
        return HttpUtility.HtmlEncode(input);
    }


    // ALL MY ACTION METHODS

    // Action Method for Forgot Password
    [HttpPost]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
    {
        if (!ModelState.IsValid) return View(model);

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            ViewBag.Message = "If the email exists, a reset link has been sent.";
            return View();
        }

        // Generate Reset Token
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var resetLink = Url.Action("ResetPassword", "Home", new { token, email = model.Email }, Request.Scheme);

        // Send Email
        await _emailSender.SendEmailAsync(model.Email, "Reset Password",
            $"Click <a href='{resetLink}'>here</a> to reset your password.");

        ViewBag.Message = "If the email exists, a reset link has been sent.";
        return View();
    }

    
    
    // Action Method for Reset Password
    [HttpPost]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
    {
        Console.WriteLine("🔄 Reset Password Request Initiated");

        if (!ModelState.IsValid)
        {
            Console.WriteLine("❌ ModelState validation failed.");
            return View(model);
        }

        // ✅ Retrieve user
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            Console.WriteLine("❌ User not found.");
            return RedirectToAction("Index");
        }

        // ✅ Check if the password reset token is valid
        var isTokenValid =
            await _userManager.VerifyUserTokenAsync(user, TokenOptions.DefaultProvider, "ResetPassword", model.Token);
        if (!isTokenValid)
        {
            Console.WriteLine("❌ Invalid or expired password reset token.");
            ModelState.AddModelError("", "Invalid or expired reset password token.");
            return View(model);
        }

        // ✅ Password Age Policy: Check if the password was changed recently
        double timeElapsed = (DateTime.UtcNow - user.UpdatedPasswordTime).TotalMinutes;
        Console.WriteLine($"⏳ Time since last password change: {timeElapsed} minutes");

        if (timeElapsed < 2) // Adjust the time limit as needed
        {
            Console.WriteLine("❌ User attempted to reset password too early.");
            ModelState.AddModelError("", "You are resetting your password too early. Try again later.");
            return View(model);
        }

        // ✅ Verify if new password matches the old password
        var passwordHasher = new PasswordHasher<ApplicationUser>();
        bool isSameAsCurrentPassword =
            passwordHasher.VerifyHashedPassword(user, user.PasswordHash, model.NewPassword) ==
            PasswordVerificationResult.Success;

        if (isSameAsCurrentPassword)
        {
            Console.WriteLine("❌ New password cannot be the same as the current password.");
            ModelState.AddModelError("", "New password cannot be the same as your current password.");
            return View(model);
        }

        // ✅ Password Reuse Policy: Prevent reusing the last two passwords
        bool isSameAsOldPassword1 = user.OldPasswordHash1 != null &&
                                    passwordHasher.VerifyHashedPassword(user, user.OldPasswordHash1,
                                        model.NewPassword) == PasswordVerificationResult.Success;

        bool isSameAsOldPassword2 = user.OldPasswordHash2 != null &&
                                    passwordHasher.VerifyHashedPassword(user, user.OldPasswordHash2,
                                        model.NewPassword) == PasswordVerificationResult.Success;

        Console.WriteLine($"🔍 Checking against Old Password 1: {user.OldPasswordHash1}");
        Console.WriteLine($"🔍 Checking against Old Password 2: {user.OldPasswordHash2}");
        Console.WriteLine($"🔍 Is same as Old Password 1? {isSameAsOldPassword1}");
        Console.WriteLine($"🔍 Is same as Old Password 2? {isSameAsOldPassword2}");

        if (isSameAsOldPassword1 || isSameAsOldPassword2)
        {
            Console.WriteLine("❌ New password matches one of the last two passwords.");
            ModelState.AddModelError("", "New password cannot be the same as your previous 2 passwords.");
            return View(model);
        }

        // ✅ Reset the password securely
        var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
        if (!result.Succeeded)
        {
            Console.WriteLine("❌ Password reset failed due to validation errors.");
            foreach (var error in result.Errors)
            {
                Console.WriteLine($"🔹 Identity Error: {error.Description}");
                ModelState.AddModelError("", error.Description);
            }

            return View(model);
        }

        // ✅ Update password history and timestamp
        string newPasswordHash = passwordHasher.HashPassword(user, model.NewPassword);
        user.OldPasswordHash2 = user.OldPasswordHash1; // Move previous password back
        user.OldPasswordHash1 = newPasswordHash; // Store the latest password
        user.UpdatedPasswordTime = DateTime.UtcNow;

        await _userManager.UpdateAsync(user);

        Console.WriteLine("✅ Password reset successfully! Redirecting to Login page.");
        TempData["SuccessMessage"] = "Password has been reset successfully!";
        return RedirectToAction("Login");
    }


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


        Console.WriteLine("🛠️ Sanitizing Inputs Now...");

// ✅ Sanitize Inputs to Prevent XSS
        Console.WriteLine($"🔹 Original First Name: {model.FirstName}");
        model.FirstName = SanitizeInput(model.FirstName);
        Console.WriteLine($"✅ Sanitized First Name: {model.FirstName}");

        Console.WriteLine($"🔹 Original Last Name: {model.LastName}");
        model.LastName = SanitizeInput(model.LastName);
        Console.WriteLine($"✅ Sanitized Last Name: {model.LastName}");

        Console.WriteLine($"🔹 Original Email: {model.Email}");
        model.Email = SanitizeInput(model.Email);
        Console.WriteLine($"✅ Sanitized Email: {model.Email}");

        Console.WriteLine($"🔹 Original Billing Address: {model.BillingAddress}");
        model.BillingAddress = SanitizeInput(model.BillingAddress);
        Console.WriteLine($"✅ Sanitized Billing Address: {model.BillingAddress}");

        Console.WriteLine($"🔹 Original Phone Number: {model.PhoneNumber}");
        model.PhoneNumber = SanitizeInput(model.PhoneNumber);
        Console.WriteLine($"✅ Sanitized Phone Number: {model.PhoneNumber}");

        Console.WriteLine($"🔹 Original Password: {model.Password}");
        model.Password = SanitizeInput(model.Password);
        Console.WriteLine($"✅ Sanitized Password: {model.Password}");

        Console.WriteLine($"🔹 Original Confirm Password: {model.ConfirmPassword}");
        model.ConfirmPassword = SanitizeInput(model.ConfirmPassword);
        Console.WriteLine($"✅ Sanitized Confirm Password: {model.ConfirmPassword}");

// ✅ Shipping Address should allow ALL special characters, but encode before displaying in the app
        Console.WriteLine($"🔹 Original Shipping Address: {model.ShippingAddress}");
        model.ShippingAddress = HttpUtility.HtmlEncode(model.ShippingAddress);
        Console.WriteLine($"✅ HTML Encoded Shipping Address: {model.ShippingAddress}");

        Console.WriteLine("✅ Sanitization Complete!");


        Console.WriteLine("🛠 Creating new ApplicationUser object...");

        // Create a new user object from ApplicationUser
        var user = new ApplicationUser
        {
            UserName = model.Email, // Identity requires a unique username, using email as default
            Email = model.Email,
            PhoneNumber = model.PhoneNumber,
            FirstName = model.FirstName,
            LastName = model.LastName,
            BillingAddress = model.BillingAddress,
            ShippingAddress = model.ShippingAddress
        };

        Console.WriteLine($"✅ Created user object: {user.Email}");


        // ✅ Encrypt and store credit card number using EncryptionService
        try
        {
            Console.WriteLine("🔒 Encrypting credit card...");
            user.GetType().GetProperty("EncryptedCreditCard")
                .SetValue(user, _encryptionService.Encrypt(model.CreditCardNumber));
            Console.WriteLine("✅ Credit card encrypted successfully");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error encrypting credit card: {ex.Message}");
            ModelState.AddModelError("", "There was an error processing your credit card. Please try again.");
            return View(model);
        }


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

        Console.WriteLine($"🔎 Checking user login for email: {model.Email}");


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

        Console.WriteLine("✅ User found in database!");

        var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);

        if (result.Succeeded)
        {
            Console.WriteLine($"✅ Login Successful! User: {user.Email}");

            // ✅ Generate a new unique session token
            string newAuthToken = Guid.NewGuid().ToString();

            // ✅ Invalidate previous session by clearing old token in DB
            user.AuthToken = newAuthToken;
            user.LastLoginTime = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // ✅ Store session data
            HttpContext.Session.SetString("UserId", user.Id);
            HttpContext.Session.SetString("AuthToken", newAuthToken);

            // ✅ Store the "LoggedIn" session variable here
            HttpContext.Session.SetString("LoggedIn", user.Email);

            Response.Cookies.Append("AuthToken", newAuthToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddHours(1)
            });

            return RedirectToAction("Home", "Home");
        }

        Console.WriteLine("❌ Login failed: Incorrect password.");
        ModelState.AddModelError("", "Invalid email or password.");
        return View(model);
    }


    [Authorize]
    [HttpPost]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
    {
        Console.WriteLine("🔄 Change Password Request Initiated");

        if (!ModelState.IsValid)
        {
            Console.WriteLine("❌ ModelState validation failed.");
            return View(model);
        }

        string userId = HttpContext.Session.GetString("UserId");

        // ✅ Retrieve user
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            Console.WriteLine("❌ User not found in database.");
            ModelState.AddModelError("", "User not found.");
            return View(model);
        }

        // ✅ Check if password was changed within the last 5 minutes
        double timeElapsed = (DateTime.UtcNow - user.UpdatedPasswordTime).TotalMinutes;

        Console.WriteLine($"⏳ Time since last password change: {timeElapsed} minutes");

        if (timeElapsed < 2)
        {
            Console.WriteLine("❌ User attempted to change password too early.");
            ModelState.AddModelError("", "You are changing password too early. Try again later.");
            return View(model);
        }

        // ✅ Verify old password
        var passwordCheck = await _userManager.CheckPasswordAsync(user, model.OldPassword);
        if (!passwordCheck)
        {
            Console.WriteLine("❌ Incorrect old password entered.");
            ModelState.AddModelError("", "Wrong old password.");
            return View(model);
        }

        // ✅ Hashing service from UserManager
        var passwordHasher = new PasswordHasher<ApplicationUser>();

// ✅ // ✅ Check if new password matches any of the last two stored passwords
        bool isSameAsOldPassword1 = user.OldPasswordHash1 != null &&
                                    passwordHasher.VerifyHashedPassword(user, user.OldPasswordHash1,
                                        model.NewPassword) == PasswordVerificationResult.Success;

        bool isSameAsOldPassword2 = user.OldPasswordHash2 != null &&
                                    passwordHasher.VerifyHashedPassword(user, user.OldPasswordHash2,
                                        model.NewPassword) == PasswordVerificationResult.Success;

// ✅ Log debug messages
        Console.WriteLine($"🔍 Checking against Old Password 1: {user.OldPasswordHash1}");
        Console.WriteLine($"🔍 Checking against Old Password 2: {user.OldPasswordHash2}");
        Console.WriteLine($"🔍 Is same as Old Password 1? {isSameAsOldPassword1}");
        Console.WriteLine($"🔍 Is same as Old Password 2? {isSameAsOldPassword2}");

        if (isSameAsOldPassword1 || isSameAsOldPassword2)
        {
            Console.WriteLine("❌ New password matches one of the last two passwords.");
            ModelState.AddModelError("", "New password cannot be the same as your previous 2 passwords.");
            return View(model);
        }

// ✅ Hash and store the new password
        string newPasswordHash = passwordHasher.HashPassword(user, model.NewPassword);

        // ✅ Update password securely
        var changeResult = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
        if (!changeResult.Succeeded)
        {
            Console.WriteLine("❌ Password change failed due to validation errors.");
            foreach (var error in changeResult.Errors)
            {
                Console.WriteLine($"🔹 Identity Error: {error.Description}");
                ModelState.AddModelError("", error.Description);
            }

            return View(model);
        }

        // ✅ Update password history and timestamp
        user.OldPasswordHash2 = user.OldPasswordHash1; // Move previous password back
        user.OldPasswordHash1 = newPasswordHash; // Store the latest password
        user.UpdatedPasswordTime = DateTime.UtcNow;

        await _userManager.UpdateAsync(user);

        // ✅ Re-sign the user after password change
        await _signInManager.SignOutAsync();
        await _signInManager.PasswordSignInAsync(user, model.NewPassword, isPersistent: false, lockoutOnFailure: false);

        Console.WriteLine("✅ Password changed successfully! Redirecting to Home page.");
        TempData["SuccessMessage"] = "Password changed successfully!";
        return RedirectToAction("Home", "Home");
    }


    // Action Method for Logout
    [HttpPost]
    public async Task<IActionResult> ConfirmLogout()
    {
        Console.WriteLine("🚪 Logging out user...");

        // ✅ Get user from session
        var userId = HttpContext.Session.GetString("UserId");

        if (!string.IsNullOrEmpty(userId))
        {
            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.Id == userId);
            if (user != null)
            {
                Console.WriteLine($"🔹 Invalidating session for user: {user.Email}");

                // ✅ Invalidate session token in the database
                user.AuthToken = null;
                await _userManager.UpdateAsync(user);
            }
        }

        // ✅ Clear session data
        HttpContext.Session.Clear();

        // ✅ Abandon session (ensures a new session is created for the next request)
        HttpContext.Session.Remove("UserId");
        HttpContext.Session.Remove("LoggedIn");
        HttpContext.Session.Remove("AuthToken");

        // ✅ Delete session-related cookies
        if (Request.Cookies.ContainsKey(".AspNetCore.Session"))
        {
            Response.Cookies.Append(".AspNetCore.Session", "", new CookieOptions
            {
                Expires = DateTime.UtcNow.AddMonths(-20),
                HttpOnly = true,
                Secure = true
            });
        }

        if (Request.Cookies.ContainsKey("AuthToken"))
        {
            Response.Cookies.Append("AuthToken", "", new CookieOptions
            {
                Expires = DateTime.UtcNow.AddMonths(-20),
                HttpOnly = true,
                Secure = true
            });
        }

        // ✅ Sign out the user
        await _signInManager.SignOutAsync();

        // ✅ Redirect to Login page
        return RedirectToAction("Login", "Home");
    }


    // Action Method for CancelLogoutButton
    [HttpPost]
    public IActionResult CancelLogout()
    {
        return RedirectToAction("Home", "Home");
    }
}