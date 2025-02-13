using Microsoft.AspNetCore.Mvc;
using BookwormsOnline_Trial4.Models;

public class ErrorController : Controller
{
    [Route("error/{code}")]
    public IActionResult Index(int code)
    {
        var model = new ErrorViewModel { StatusCode = code, RequestId = HttpContext.TraceIdentifier };

        if (code == 404)
            return View("NotFound", model);
        if (code == 500)
            return View("ServerError", model);
        
        return View("Error", model); // Default error page for other errors
    }
}