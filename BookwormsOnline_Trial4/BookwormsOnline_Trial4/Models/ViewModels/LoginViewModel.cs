using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace BookwormsOnline_Trial4.Models.ViewModels
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "Email is required.")]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required.")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        public bool RememberMe { get; set; }

        // New property to store login erro
    }
}