using System;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace BookwormsOnline_Trial4.Services
{
    public class CaptchaService
    {
        private readonly IConfiguration _configuration;
        private readonly HttpClient _httpClient;

        public CaptchaService(IConfiguration configuration, HttpClient httpClient)
        {
            _configuration = configuration;
            _httpClient = httpClient;
        }

        public async Task<bool> ValidateCaptchaAsync(string captchaResponse)
        {
            if (string.IsNullOrEmpty(captchaResponse))
            {
                Console.WriteLine("❌ No Captcha Response Received!");
                return false;
            }

            string secretKey = _configuration["Recaptcha:SecretKey"];
            string apiUrl = $"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={captchaResponse}";

            try
            {
                HttpResponseMessage response = await _httpClient.GetAsync(apiUrl);
                response.EnsureSuccessStatusCode();

                string jsonResponse = await response.Content.ReadAsStringAsync();
                Console.WriteLine("🔍 Google reCAPTCHA Response: " + jsonResponse); // ✅ Debug Log
                
                
                CaptchaResult result = JsonSerializer.Deserialize<CaptchaResult>(jsonResponse);
                
                Console.WriteLine("This is the result after deseralising" + result);
                
                Console.WriteLine("✅ reCAPTCHA Success Value: " + result.Success);
                return result?.Success ?? false;
            }
            catch (Exception ex)
            {
                Console.WriteLine("❌ Error validating reCAPTCHA: " + ex.Message);
                return false;
            }
        }
    }

    public class CaptchaResult
    {
        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("challenge_ts")]
        public string ChallengeTimestamp { get; set; }

        [JsonPropertyName("hostname")]
        public string Hostname { get; set; }

        [JsonPropertyName("score")]
        public float Score { get; set; }

        [JsonPropertyName("action")]
        public string Action { get; set; }

        [JsonPropertyName("error-codes")]
        public string[] ErrorCodes { get; set; }
    }
}