using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using BookwormsOnline_Trial4.Models;

namespace BookwormsOnline_Trial4.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;

    public HomeController(ILogger<HomeController> logger)
    {
        _logger = logger;
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
    
    
    // Action Method for Login
    
    
    
    
    
    
    
    
    
    
    
    
    
    

 

    
}