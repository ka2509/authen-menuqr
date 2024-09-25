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
                    return BadRequest(new { message = "Invalid input data.", errors = ModelState });
                }

                // Check if email or phone number already exists
                var existingUser = await _users.Find(u => u.Email == registerDto.Email || u.PhoneNumber == registerDto.PhoneNumber).FirstOrDefaultAsync();
                if (existingUser != null)
                {
                    return Conflict(new { message = "Email or phone number already exists." });
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

                return Ok(new { message = "User registered successfully.", token });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = "An error occurred during registration.", details = ex.Message });
            }
        }
        // user click on the sign-in with google then front end will trigger this login api to send user to the Google login page.
        public async Task Login()
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

                if (string.IsNullOrEmpty(emailClaim))
                {
                    return BadRequest(new { message = "No email found in the claims." });
                }

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

                    return Ok(new { message = "User created successfully.", token });
                }
                // if user already exists => generate token
                var existingUserToken = _tokenService.CreateToken(existingUser);
                return Ok(new { message = "User logged in successfully.", token = existingUserToken });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = "An error occurred during Google authentication.", details = ex.Message });
            }
        }
    }
}
