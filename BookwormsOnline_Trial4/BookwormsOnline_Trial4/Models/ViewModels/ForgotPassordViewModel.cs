using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline_Trial4.Models.ViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required, EmailAddress]
        public string Email { get; set; }
    }
}