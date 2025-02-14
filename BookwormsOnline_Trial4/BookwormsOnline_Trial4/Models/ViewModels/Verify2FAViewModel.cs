using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline_Trial4.Models.ViewModels
{
    public class Verify2FAViewModel
    {
        [Required]
        public string Email { get; set; }

        [Required]
        [StringLength(6, MinimumLength = 6, ErrorMessage = "OTP must be 6 digits.")]
        public string OTP { get; set; }
    }
}