using System.ComponentModel.DataAnnotations;

namespace MenuQr.Dtos
{
    public class LoginDto
    {
        [Required]
        public string? Username { get; set; } // Accepts either email or phone number
        [Required]
        public string? Password { get; set; }
    }
}
