using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using MenuQr.Models;
using MongoDB.Driver;
using MenuQr.Data;
using System.Security.Claims;
using MenuQr.Services;
using MenuQr.Dtos;

namespace MenuQr.Controllers
{
    [ApiController]
    [Route("api/login")]
    public class LoginController : ControllerBase
    {
        private readonly IMongoCollection<User> _users;
        private readonly TokenService _tokenService;

        public LoginController(MongoDbService mongoDbService, TokenService tokenService)
        {
            _users = mongoDbService.Database?.GetCollection<User>("user");
            _tokenService = tokenService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new { message = "Thông tin không hợp lệ.", errors = ModelState });
                }

                // Check if email or phone number already exists
                var existingUser = await _users.Find(u => u.Email == registerDto.Email || u.PhoneNumber == registerDto.PhoneNumber).FirstOrDefaultAsync();
                if (existingUser != null)
                {
                    return Conflict(new { message = "Số điện thoại hoặc địa chỉ email đã được đăng ký." });
                }

                // Hash password
                var hashedPassword = BCrypt.Net.BCrypt.HashPassword(registerDto.Password);

                var user = new User
                {
                    FirstName = registerDto.FirstName,
                    LastName = registerDto.LastName,
                    Email = registerDto.Email,
                    PhoneNumber = registerDto.PhoneNumber,
                    Password = hashedPassword
                };

                // Insert new user
                await _users.InsertOneAsync(user);

                // Generate token
                var token = _tokenService.CreateToken(user);

                return Ok(new { message = "Người dùng đã đăng ký thành công.", token });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = "Lỗi xảy ra trong quá trình đăng ký.", details = ex.Message });
            }
        }
        // user click on the sign-in with google then front end will trigger this login api to send user to the Google login page.
        [HttpGet("login-with-google")]
        public async Task LoginWithGoogle()
        {
            await HttpContext.ChallengeAsync(GoogleDefaults.AuthenticationScheme,
                new AuthenticationProperties
                {
                    RedirectUri = Url.Action("GoogleResponse") // Where Google will send the response back
                });
        }

        // after user entered their Google account credentials, Google handles the authentication and redirects the user back to this API
        public async Task<IActionResult> GoogleResponse()
        {
            try
            {
                var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                // Extract user claims
                var claimsIdentity = result.Principal?.Identities.FirstOrDefault();
                if (claimsIdentity == null)
                {
                    return Unauthorized(new { message = "No user identity found." });
                }

                var emailClaim = claimsIdentity.FindFirst(ClaimTypes.Email)?.Value;
                var firstNameClaim = claimsIdentity.FindFirst(ClaimTypes.GivenName)?.Value;
                var lastNameClaim = claimsIdentity.FindFirst(ClaimTypes.Surname)?.Value;


                // Check if user already exists in the database
                var existingUser = await _users.Find(u => u.Email == emailClaim).FirstOrDefaultAsync();
                if (existingUser == null)
                {
                    // Create new user if not found
                    var newUser = new User
                    {
                        FirstName = firstNameClaim ?? string.Empty,
                        LastName = lastNameClaim ?? string.Empty,
                        Email = emailClaim,
                    };

                    await _users.InsertOneAsync(newUser);
                    var token = _tokenService.CreateToken(newUser);

                    return Ok(new { message = "Người dùng tạo tài khoản thành công.", token });
                }
                // if user already exists => generate token
                var existingUserToken = _tokenService.CreateToken(existingUser);
                return Ok(new { message = "Người dùng đăng nhập thành công.", token = existingUserToken });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = "Có lỗi xảy ra trong quá trình đăng nhập.", details = ex.Message });
            }
        }
        [HttpPost]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new { message = "Thông tin không hợp lệ.", errors = ModelState });
            }

            // Check if the username is an email or phone number
            var user = await _users.Find(u =>
                u.Email == loginDto.Username ||
                u.PhoneNumber == loginDto.Username).FirstOrDefaultAsync();

            if (user == null)
            {
                return Unauthorized(new { message = "Người dùng không tồn tại." });
            }

            // Verify password
            if (!BCrypt.Net.BCrypt.Verify(loginDto.Password, user.Password))
            {
                return Unauthorized(new { message = "Mật khẩu sai." });
            }

            // Generate token
            var token = _tokenService.CreateToken(user);
            return Ok(new { message = "Người dùng đăng nhập thành công.", token });
        }

    }
}
