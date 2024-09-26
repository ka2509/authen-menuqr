using MenuQr.Utils.Validations;
using System.ComponentModel.DataAnnotations;

namespace MenuQr.Dtos
{
    public class LoginDto
    {
        [Required(ErrorMessage = "Email hoặc Số điện thoại là bắt buộc.")]
        [EmailOrPhone]
        public string? Username { get; set; }
        [Required]
        [MinLength(6, ErrorMessage = "Mật khẩu phải có ít nhất 6 ký tự.")]
        public string? Password { get; set; }
    }
}
