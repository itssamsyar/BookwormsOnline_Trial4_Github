using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline_Trial4.Models.ViewModels
{
    public class RegisterViewModel
    {
        [Required]
        [StringLength(50, MinimumLength = 2, ErrorMessage = "First name must be between 2 and 50 characters.")]
        [RegularExpression(@"^[A-Za-z\s]+$", ErrorMessage = "First name can only contain letters and spaces.")]
        public string FirstName { get; set; }

        [Required]
        [StringLength(50, MinimumLength = 2, ErrorMessage = "Last name must be between 2 and 50 characters.")]
        [RegularExpression(@"^[A-Za-z\s]+$", ErrorMessage = "Last name can only contain letters and spaces.")]
        public string LastName { get; set; }


        [Required]
        [EmailAddress(ErrorMessage = "Invalid email format.")]
        [StringLength(100, MinimumLength = 5, ErrorMessage = "Email must be between 5 and 100 characters.")]
        public string Email { get; set; }

        [Required]
        [StringLength(255, MinimumLength = 5, ErrorMessage = "Billing address must be between 5 and 255 characters.")]
        public string BillingAddress { get; set; }

        [Required]
        [StringLength(255, MinimumLength = 5, ErrorMessage = "Shipping address must be between 5 and 255 characters.")]
        public string ShippingAddress { get; set; } // Allowed to contain ALL special characters

        [Required]
        [Phone(ErrorMessage = "Invalid phone number format.")]
        [StringLength(15, MinimumLength = 8, ErrorMessage = "Phone number must be between 8 and 15 digits.")]
        public string PhoneNumber { get; set; }

        [Required]
        [DataType(DataType.CreditCard)]
        [RegularExpression(@"^\d{16}$", ErrorMessage = "Credit Card number must be 16 digits.")]
        public string CreditCardNumber { get; set; }

        [Required]
        [DataType(DataType.Upload)]
        public IFormFile Photo { get; set; }

        [Required]
        [MinLength(12, ErrorMessage = "Enter at least a 12-character password")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_])[A-Za-z\d\W_]{12,}$",
            ErrorMessage = "Password must be at least 12 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.")]
        public string Password { get; set; }

        [Required]
        [Compare("Password", ErrorMessage = "Passwords do not match.")]
        public string ConfirmPassword { get; set; }

        [Required]
        public string gRecaptchaResponse { get; set; } // Captcha Response Token
    }
}
