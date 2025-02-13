using Microsoft.AspNetCore.DataProtection;

namespace BookwormsOnline_Trial4.Services
{
    public class EncryptionService
    {
        private readonly IDataProtector _protector;
        public EncryptionService(IDataProtectionProvider provider)
        {
            _protector = provider.CreateProtector("CreditCardProtector");
        }
        public string Encrypt(string plainText)
        {
            return _protector.Protect(plainText);
        }
        public string Decrypt(string cipherText)
        {
            return _protector.Unprotect(cipherText);
        }
    }
}

