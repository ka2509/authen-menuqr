using MenuQr.Data;
using MenuQr.Dtos;
using MenuQr.Models;
using MenuQr.Services;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;

namespace MenuQr.Controllers
{
    [ApiController]
    [Route("api/token")]
    public class TokenController : ControllerBase
    {
        private readonly TokenService _tokenService;
        private readonly IMongoCollection<User> _users;
        public TokenController(MongoDbService mongoDbService, TokenService tokenService)
        {
            _tokenService = tokenService;
            _users = mongoDbService.Database?.GetCollection<User>("user");
        }
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] TokenDto tokenDto)
        {
            var user = await _users.Find(u => u.RefreshToken == tokenDto.RefreshToken).FirstOrDefaultAsync();

            if (user == null || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return Unauthorized(new { message = "Refresh token không hợp lệ hoặc đã quá hạn." });
            }

            // Update refresh token and expiry time
            var newRefreshToken = _tokenService.GenerateRefreshToken();
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);
            await _users.ReplaceOneAsync(u => u.Id == user.Id, user);

            // Generate new tokens
            var newToken = _tokenService.CreateToken(user);


            return Ok(new {message = "Refresh token thành công.", newToken});
        }
    }
}
