



using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.DataProtection;

namespace BookwormsOnline_Trial4.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        [StringLength(50)]
        public string FirstName { get; set; }

        [Required]
        [StringLength(50)]
        public string LastName { get; set; }

        [Required]
        public string EncryptedCreditCard { get; private set; }

        [Required]
        [StringLength(255)]
        public string BillingAddress { get; set; }

        [Required]
        [StringLength(255)]
        public string ShippingAddress { get; set; }

        public string PhotoPath { get; set; } // Stores file path instead of byte array

        
        // EMAIL, PASSWORD, PHONE_NUMBER WILL BE HANDLED BY IDENTITY USER ITSELF
        
        
        
        // ADDITIONAL FIELDS FOR THE ADVANCED FEATURES ARE LISTED BELOW
        
        
        
        // PASSWORD REUSE POLICY
        public string? OldPasswordHash1 { get; set; } // Previous password
        public string? OldPasswordHash2 { get; set; } // 2nd most recent password
        
        // PASSWORD AGE POLICY
        public DateTime UpdatedPasswordTime { get; set; } 
        
        
        // TRACKING SESSIONS
        
        
        
        
        
        public string? AuthToken { get; set; } = string.Empty;   // Stores session identifier
        public DateTime? LastLoginTime { get; set; }  // Tracks last login
        
        
        // FOR 2FA LOGIN
        // ✅ Store the generated OTP code for 2FA
        public string? TwoFactorCode { get; set; }

        // ✅ Store when the OTP expires
        public DateTime? TwoFactorExpiry { get; set; }
        
        
        // FOR ACCOUNT LOCKOUT
        // ✅ Track failed login attempts
        public int FailedLoginAttempts { get; set; } = 0;

        // ✅ Store the time when the account was locked
        public DateTime? LockoutEndTime { get; set; }

        
    }
}