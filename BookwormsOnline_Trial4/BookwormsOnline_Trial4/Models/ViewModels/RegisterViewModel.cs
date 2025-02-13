using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline_Trial4.Models.ViewModels
{
    public class RegisterViewModel
    {
        
        // REMEMBER TO PUT IN ALL THE VALIDATION THAT YOU NEED + ALL THE FIELDS THAT YOU NEED
        
        
        [Required]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Password and confirmation password do not match")]
        public string ConfirmPassword { get; set; }
        
        [Required]
        public string gRecaptchaResponse { get; set; } // Captcha Response Token
    }
}