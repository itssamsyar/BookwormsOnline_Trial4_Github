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
            DecryptedCreditCard = decryptedCreditCard,
            
            TwoFactorEnabled = user.TwoFactorEnabled // ✅ Pass 2FA status to View
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
    
    // Loads the /Home/Verify2FA.cshtml
    [HttpGet]
    public IActionResult Verify2FA(string email)
    {
        return View(new Verify2FAViewModel { Email = email });
    }

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    // EXTRA METHODS FOR FUNCTIONALITY

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
    
    // Action Method for Audit Logs
    private async Task LogAudit(string userId, string email, string action)
    {
        var auditLog = new AuditLog
        {
            UserId = userId,
            Email = email,
            Action = action,
            IPAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
        };

        _context.AuditLogs.Add(auditLog);
        await _context.SaveChangesAsync();
    }

    
    
    // Action Method for Toggling TwoFactorEnabled on or off
    [HttpPost]
    public async Task<IActionResult> ToggleTwoFactor(string email)
    {
        Console.WriteLine($"🔄 Toggling 2FA for {email}");

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            Console.WriteLine("❌ User not found!");
            return RedirectToAction("Home");
        }

        // ✅ Invert the current TwoFactorEnabled value
        user.TwoFactorEnabled = !user.TwoFactorEnabled;

        var result = await _userManager.UpdateAsync(user);
    
        if (!result.Succeeded)
        {
            Console.WriteLine("❌ Error updating TwoFactorEnabled in the database.");
            foreach (var error in result.Errors)
            {
                Console.WriteLine($"🔴 Error: {error.Description}");
            }
        }
        else
        {
            Console.WriteLine($"✅ 2FA for {email} updated to: {user.TwoFactorEnabled}");
        }

        // ✅ Refresh user session to apply changes immediately
        await _signInManager.RefreshSignInAsync(user);

        return RedirectToAction("Home");
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
        
        // ✅ Log Password Reset Request
        await LogAudit(user.Id, user.Email, "Password Reset Requested");
        
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
        
        // ✅ Log Password Reset Success
        await LogAudit(user.Id, user.Email, "Password Reset Completed");
        
        
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
            ShippingAddress = model.ShippingAddress,
            
            TwoFactorEnabled = true
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
            
            // ✅ Log Registration Event
            await LogAudit(user.Id, user.Email, "User Registered");
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
        
        // ✅ Check if the account is locked
        if (user.LockoutEndTime.HasValue && user.LockoutEndTime > DateTime.UtcNow)
        {
            Console.WriteLine($"❌ Account is locked until {user.LockoutEndTime.Value}");
            ModelState.AddModelError("", $"Your account is locked. Try again after {user.LockoutEndTime.Value:HH:mm:ss} UTC.");
            return View(model);
        }

        var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);

        if (result.Succeeded)
        {
            Console.WriteLine($"✅ Password is correct. Initiating 2FA for: {user.Email}");
            
            
            // ✅ Reset failed login attempts on successful login
            user.FailedLoginAttempts = 0;
            user.LockoutEndTime = null;
            await _userManager.UpdateAsync(user);

            // ✅ Check if Two-Factor Authentication is enabled
            if (user.TwoFactorEnabled)
            {
                Console.WriteLine($"🔐 2FA is enabled for {user.Email}. Generating OTP...");

                // ✅ Generate a 6-digit OTP
                var otpCode = new Random().Next(100000, 999999).ToString();
                user.TwoFactorCode = otpCode;
                user.TwoFactorExpiry = DateTime.UtcNow.AddMinutes(5); // Set expiry time (5 mins)
                await _userManager.UpdateAsync(user);

                // ✅ Send the OTP via Email
                await _emailSender.SendEmailAsync(user.Email, "Your 2FA Code",
                    $"Your One-Time Password (OTP) for login is: <b>{otpCode}</b>. This code expires in 5 minutes.");

                Console.WriteLine($"📧 OTP Sent to Email: {user.Email}");
                
                // ✅ Log OTP Sent Event
                await LogAudit(user.Id, user.Email, "2FA OTP Sent");

                // ✅ Redirect to OTP verification page
                return RedirectToAction("Verify2FA", new { email = user.Email });
            }
            else
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
                
                // ✅ Log Login Event
                await LogAudit(user.Id, user.Email, "User Login");


                return RedirectToAction("Home", "Home");
            }
        }
        
        // ❌ Login Failed: Increment Failed Attempts
        user.FailedLoginAttempts++;
        
        // ❌ Log Failed Login Attempt
        await LogAudit(user.Id, user.Email, "Failed Login Attempt");

        // ✅ Check if the user has reached 3 failed attempts
        if (user.FailedLoginAttempts >= 3)
        {
            Console.WriteLine("❌ User exceeded failed login attempts! Locking account.");
            user.LockoutEndTime = DateTime.UtcNow.AddMinutes(5); // Lock for 5 minutes
            
            // ✅ Log Account Lockout Event
            await LogAudit(user.Id, user.Email, "Account Locked Out");
            
            ModelState.AddModelError("", "Your account has been locked due to multiple failed login attempts. Try again after 5 minutes.");
        }
        else
        {
          
            
            int attemptsLeft = 3 - user.FailedLoginAttempts;
            Console.WriteLine($"❌ Incorrect password. {attemptsLeft} attempt(s) left.");
            ModelState.AddModelError("", $"Invalid email or password. {attemptsLeft} attempt(s) left before lockout.");
        }

        await _userManager.UpdateAsync(user);

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

// ✅ Check if new password matches the current password or any of the last two stored passwords
        bool isSameAsCurrentPassword = user.PasswordHash != null &&
                                       passwordHasher.VerifyHashedPassword(user, user.PasswordHash, model.NewPassword) 
                                       == PasswordVerificationResult.Success;

        bool isSameAsOldPassword1 = user.OldPasswordHash1 != null &&
                                    passwordHasher.VerifyHashedPassword(user, user.OldPasswordHash1, model.NewPassword) 
                                    == PasswordVerificationResult.Success;

        bool isSameAsOldPassword2 = user.OldPasswordHash2 != null &&
                                    passwordHasher.VerifyHashedPassword(user, user.OldPasswordHash2, model.NewPassword) 
                                    == PasswordVerificationResult.Success;

// ✅ Log debug messages
        Console.WriteLine($"🔍 Checking against Current Password: {user.PasswordHash}");
        Console.WriteLine($"🔍 Checking against Old Password 1: {user.OldPasswordHash1}");
        Console.WriteLine($"🔍 Checking against Old Password 2: {user.OldPasswordHash2}");
        Console.WriteLine($"🔍 Is same as Current Password? {isSameAsCurrentPassword}");
        Console.WriteLine($"🔍 Is same as Old Password 1? {isSameAsOldPassword1}");
        Console.WriteLine($"🔍 Is same as Old Password 2? {isSameAsOldPassword2}");

// ✅ Enforce password policy: Reject if new password matches any of the previous ones
        if (isSameAsCurrentPassword || isSameAsOldPassword1 || isSameAsOldPassword2)
        {
            Console.WriteLine("❌ New password matches with the current password.");
            ModelState.AddModelError("", "New password cannot be the same as your current password.");
            return View(model);

            
        }


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
        
        // ✅ Log Password Change Event
        await LogAudit(user.Id, user.Email, "Password Changed");
        
        TempData["SuccessMessage"] = "Password changed successfully!";
        return RedirectToAction("Home", "Home");
    }
    
    
    [HttpPost]
    public async Task<IActionResult> Verify2FA(Verify2FAViewModel model)
    {
        Console.WriteLine($"🔍 Verifying 2FA for Email: {model.Email}");

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            Console.WriteLine("❌ User not found!");
            ModelState.AddModelError("", "Invalid request.");
            return View(model);
        }

        // ✅ Check if OTP is expired
        if (user.TwoFactorExpiry < DateTime.UtcNow)
        {
            Console.WriteLine("❌ OTP Expired.");
            ModelState.AddModelError("", "Your OTP has expired. Please login again.");
            return View(model);
        }

        // ✅ Check if OTP matches
        if (user.TwoFactorCode != model.OTP)
        {
            Console.WriteLine("❌ Invalid OTP.");
            ModelState.AddModelError("", "Invalid OTP. Please try again.");
            return View(model);
        }

        Console.WriteLine("✅ OTP Verified Successfully!");

        // ✅ Generate a new session token & update last login time
        string newAuthToken = Guid.NewGuid().ToString();
        
        user.AuthToken = newAuthToken;
        user.LastLoginTime = DateTime.UtcNow;
        
        await _userManager.UpdateAsync(user);

        // ✅ Store session data
        HttpContext.Session.SetString("UserId", user.Id);
        HttpContext.Session.SetString("AuthToken", newAuthToken);
        HttpContext.Session.SetString("LoggedIn", user.Email);

        Response.Cookies.Append("AuthToken", newAuthToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.UtcNow.AddHours(1)
        });
        
        // ✅ Log Login Event
        await LogAudit(user.Id, user.Email, "User Login");


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
                
                await LogAudit(user.Id, user.Email, "User Logged Out");

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