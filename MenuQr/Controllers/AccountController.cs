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
using Microsoft.AspNetCore.Authentication.Facebook;

namespace MenuQr.Controllers
{
    [ApiController]
    [Route("api/account")]
    public class AccountController : ControllerBase
    {
        private readonly IMongoCollection<User> _users;
        private readonly TokenService _tokenService;

        public AccountController(MongoDbService mongoDbService, TokenService tokenService)
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
                // tạo ra refresh token và lưu vào database trước 
                var user = new User
                {
                    FirstName = registerDto.FirstName,
                    LastName = registerDto.LastName,
                    Email = registerDto.Email,
                    PhoneNumber = registerDto.PhoneNumber,
                    Password = hashedPassword,
                    RefreshToken = _tokenService.GenerateRefreshToken(),
                    RefreshTokenExpiryTime = DateTime.Now.AddDays(7)
                };
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
        [HttpGet("google-response")]
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
                        RefreshToken = _tokenService.GenerateRefreshToken(),
                        RefreshTokenExpiryTime = DateTime.Now.AddDays(7)
                    };

                    await _users.InsertOneAsync(newUser);
                    var token = _tokenService.CreateToken(newUser);

                    return Ok(new { message = "Người dùng tạo tài khoản thành công.", token });
                }

                // if user already exists => update refresh token 
                existingUser.RefreshToken = _tokenService.GenerateRefreshToken();
                existingUser.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);

                await _users.ReplaceOneAsync(u => u.Id ==existingUser.Id, existingUser);

                // generate token and response
                var existingUserToken = _tokenService.CreateToken(existingUser);
                return Ok(new { message = "Người dùng đăng nhập thành công.", existingUserToken });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = "Có lỗi xảy ra trong quá trình đăng nhập.", details = ex.Message });
            }
        }
        [HttpPost("login")]
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
            // if password correct then update the refresh token
            user.RefreshToken = _tokenService.GenerateRefreshToken();
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);

            await _users.ReplaceOneAsync(u => u.Id == user.Id, user);
            // Generate token
            var token = _tokenService.CreateToken(user);
            return Ok(new { message = "Người dùng đăng nhập thành công.", token });
        }
        // API để đăng nhập qua Facebook
        [HttpGet("login-with-facebook")]
        public async Task LoginWithFacebook()
        {
            await HttpContext.ChallengeAsync(FacebookDefaults.AuthenticationScheme,
                new AuthenticationProperties
                {
                    RedirectUri = Url.Action("FacebookResponse") // Sau khi đăng nhập thành công, Facebook sẽ gửi phản hồi đến URL này
                });
        }

        // API để xử lý phản hồi từ Facebook sau khi người dùng đăng nhập thành công
        [HttpGet("facebook-response")]
        public async Task<IActionResult> FacebookResponse()
        {
            try
            {
                var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                // Lấy các claims từ Facebook
                var claimsIdentity = result.Principal?.Identities.FirstOrDefault();
                if (claimsIdentity == null)
                {
                    return Unauthorized(new { message = "No user identity found." });
                }

                var emailClaim = claimsIdentity.FindFirst(ClaimTypes.Email)?.Value;
                var firstNameClaim = claimsIdentity.FindFirst(ClaimTypes.GivenName)?.Value;
                var lastNameClaim = claimsIdentity.FindFirst(ClaimTypes.Surname)?.Value;
                // Kiểm tra xem người dùng đã tồn tại trong database chưa
                var existingUser = await _users.Find(u => u.Email == emailClaim).FirstOrDefaultAsync();
                if (existingUser == null)
                {
                    // Tạo người dùng mới nếu chưa có
                    var newUser = new User
                    {
                        FirstName = firstNameClaim ?? string.Empty,
                        LastName = lastNameClaim ?? string.Empty,
                        Email = emailClaim,
                        RefreshToken = _tokenService.GenerateRefreshToken(),
                        RefreshTokenExpiryTime = DateTime.Now.AddDays(7)
                    };

                    await _users.InsertOneAsync(newUser);
                    var token = _tokenService.CreateToken(newUser);

                    return Ok(new { message = "Người dùng tạo tài khoản thành công.", token });
                }

                // Người dùng đã tồn tại => tạo token
                existingUser.RefreshToken = _tokenService.GenerateRefreshToken();
                existingUser.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);

                await _users.ReplaceOneAsync(u => u.Id == existingUser.Id, existingUser);
                // Tạo token
                var existingUserToken = _tokenService.CreateToken(existingUser);
                return Ok(new { message = "Người dùng đăng nhập thành công.", existingUserToken });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = "Có lỗi xảy ra trong quá trình đăng nhập.", details = ex.Message });
            }
        }
        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] LogoutDto logoutDto)
        {
            var user = await _users.Find(u => u.Email == logoutDto.Email).FirstOrDefaultAsync();

            if (user == null)
            {
                return BadRequest(new { message = "Người dùng không hợp lệ." });
            }

            // Xóa refresh token của người dùng đã đăng xuất
            user.RefreshToken = null;
            user.RefreshTokenExpiryTime = DateTime.MinValue;
            await _users.ReplaceOneAsync(u => u.Id == user.Id, user);

            return Ok(new { message = "Người dùng đăng xuất thành công." });
        }
    }
}
