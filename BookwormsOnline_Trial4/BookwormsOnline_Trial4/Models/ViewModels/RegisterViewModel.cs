using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline_Trial4.Models.ViewModels
{
    public class RegisterViewModel
    {
        [Required]
        [StringLength(50, MinimumLength = 2, ErrorMessage = "First name must be between 2 and 50 characters.")]
        public string FirstName { get; set; }

        [Required]
        [StringLength(50, MinimumLength = 2, ErrorMessage = "Last name must be between 2 and 50 characters.")]
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
        public string ShippingAddress { get; set; }

        [Required]
        [Phone(ErrorMessage = "Invalid phone number format.")]
        [StringLength(15, MinimumLength = 8, ErrorMessage = "Phone number must be between 8 and 15 digits.")]
        public string PhoneNumber { get; set; }

        [Required]
        [DataType(DataType.CreditCard)]
        [RegularExpression(@"^\d{16}$", ErrorMessage = "Credit Card number must be 16 digits.")]
        public string CreditCardNumber { get; set; } // This will be encrypted before storing

        [Required]
        [DataType(DataType.Upload)]
        public IFormFile Photo { get; set; } // Handles file uploads




        [Required]
        [DataType(DataType.Password)]
        [StringLength(100, MinimumLength = 12, ErrorMessage = "Password must be at least 12 characters long.")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).+$",
            ErrorMessage =
                "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }

        [Required] public string gRecaptchaResponse { get; set; } // Captcha Response Token
    }
}