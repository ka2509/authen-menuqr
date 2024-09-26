using MenuQr.Models;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Security.Claims;
using System.Text;
using MenuQr.Dtos;
using System.Security.Cryptography;

namespace MenuQr.Services
{
    public class TokenService
    {
        private readonly IConfiguration _config;
        private readonly SymmetricSecurityKey _key;
        public TokenService(IConfiguration config)
        {
            _config = config;
            _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
        }
        public TokenDto CreateToken(User user)
        {
            var claims = new List<Claim> {
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Name, $"{user.FirstName} {user.LastName}"),
            new Claim(JwtRegisteredClaimNames.PhoneNumber, user.PhoneNumber)
           };
            var creds = new SigningCredentials(_key, SecurityAlgorithms.HmacSha512Signature);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(7),
                SigningCredentials = creds,
                Issuer = _config["JWT:Issuer"],
                Audience = _config["JWT:Audience"]
            };
            var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            // luôn update hoặc tạo refresh token trước tiên
            return new TokenDto(tokenHandler.WriteToken(token), user.RefreshToken);
        }
        // tạo mảng 32 bytes, fill bảng bằng các số ngẫu nhiên, mã hóa mảng thành một chuỗi
        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rdg = RandomNumberGenerator.Create())
            {
                rdg.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }
    }
}
