using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace MenuQr.Utils.Validations
{
    public class EmailOrPhoneAttribute : ValidationAttribute
    {
        protected override ValidationResult IsValid(object? value, ValidationContext validationContext)
        {
            if (value == null || string.IsNullOrWhiteSpace(value.ToString()))
            {
                return new ValidationResult("Email hoặc Số điện thoại là bắt buộc.");
            }

            var input = value.ToString();

            // Regex cho format email
            var emailRegex = new Regex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$");
            // Regex cho format số điện thoại việt nam
            var phoneRegex = new Regex(@"^0(3|5|7|8|9)\d{8}$");


            if (emailRegex.IsMatch(input) || phoneRegex.IsMatch(input))
            {
                return ValidationResult.Success;
            }

            return new ValidationResult("Username phải là Email hoặc Số điện thoại hợp lệ.");
        }
    }
}
