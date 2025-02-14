using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline_Trial4.Models.ViewModels
{
    public class ResetPasswordViewModel
    {
        [Required]
        public string Token { get; set; }

        [Required, EmailAddress]
        public string Email { get; set; }

        [Required(ErrorMessage = "Please enter a new password.")]
        [MinLength(12, ErrorMessage = "Enter at least a 12-character password.")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_])[A-Za-z\d\W_]{12,}$",
            ErrorMessage = "Password must be at least 12 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.")]
        public string NewPassword { get; set; }

        [Required(ErrorMessage = "Please confirm your new password.")]
        [Compare("NewPassword", ErrorMessage = "Passwords do not match.")]
        public string ConfirmPassword { get; set; }
    }
}