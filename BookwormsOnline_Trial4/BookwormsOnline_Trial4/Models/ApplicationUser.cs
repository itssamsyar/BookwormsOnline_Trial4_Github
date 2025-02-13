



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

        
        
        
        
        
        // METHODS TO ENCRYPT CREDIT CARD
        // ✅ Parameterless constructor (required by Entity Framework)
        private IDataProtector _protector;

        public ApplicationUser() { }

        // ✅ Constructor with dependency injection for encryption
        public ApplicationUser(IDataProtectionProvider provider)
        {
            _protector = provider.CreateProtector("CreditCardProtection");
        }

        // Encrypt credit card before storing in database
        public void SetEncryptedCreditCard(string creditCardNumber)
        {
            if (_protector == null)
            {
                throw new InvalidOperationException("Data protector is not initialized.");
            }
            EncryptedCreditCard = _protector.Protect(creditCardNumber);
        }

        // Decrypt credit card (for admin use only)
        public string GetDecryptedCreditCard()
        {
            if (_protector == null)
            {
                throw new InvalidOperationException("Data protector is not initialized.");
            }
            return _protector.Unprotect(EncryptedCreditCard);
        }
        
        
        
        
        
        
        
        
        
        
        
        
        // EMAIL, PASSWORD, PHONE_NUMBER WILL BE HANDLED BY IDENTITY USER ITSELF
        
        
        
        // ADDITIONAL FIELDS FOR THE ADVANCED FEATURES ARE LISTED BELOW

        
    }
}