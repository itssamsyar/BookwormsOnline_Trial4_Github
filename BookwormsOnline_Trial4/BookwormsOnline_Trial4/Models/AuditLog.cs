using System;

namespace BookwormsOnline_Trial4.Models
{
    public class AuditLog
    {
        public int Id { get; set; } // Primary Key
        public string UserId { get; set; } // Stores User ID
        public string Email { get; set; } // Stores Email (for quick reference)
        public string Action { get; set; } // Action performed (e.g., "User Login", "Password Changed")
        public string IPAddress { get; set; } // Store IP Address of the request
        public DateTime Timestamp { get; set; } = DateTime.UtcNow; // Store UTC Timestamp
    }
}