using JWTRefreshToken.Data;
using JWTRefreshToken.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using JWTRefreshToken.Models;

namespace JWTRefreshToken.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly TokenService _tokenService;

        public AuthController(ApplicationDbContext context, TokenService tokenService)
        {
            _context = context;
            _tokenService = tokenService;
        }

        [HttpPost("register")]
    public IActionResult Register([FromBody] RegisterRequest request)
    {
        // Hash the password using BCrypt
        var hashedPassword = BCrypt.Net.BCrypt.HashPassword(request.Password);  // BCrypt will handle the salt for you

        var user = new User
        {
            Username = request.Username,
            PasswordHash = hashedPassword,  // Store the hashed password (with salt)
            RefreshToken = "dummy-refresh-token-12345",  // Dummy refresh token for testing
            RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(1)  // Set the expiry to a future date
        };

        _context.Users.Add(user);
        _context.SaveChanges();

        return Ok(new { message = "User registered successfully!" });
    }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == request.Username);
            if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
                return Unauthorized(new { message = "Invalid username or password" });

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var accessToken = _tokenService.GenerateAccessToken(claims);
            var refreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(1);
            await _context.SaveChangesAsync();

            return Ok(new { accessToken, refreshToken });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
        {
            if (string.IsNullOrEmpty(request.AccessToken) || string.IsNullOrEmpty(request.RefreshToken))
                return BadRequest(new { message = "Access token or refresh token is missing" });

            var principal = _tokenService.GetPrincipalFromExpiredToken(request.AccessToken);
            if (principal == null)
                return Unauthorized(new { message = "Invalid or expired access token" });

            var username = principal.Identity.Name;
            var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == username);

            if (user == null || user.RefreshToken != request.RefreshToken || user.RefreshTokenExpiryTime < DateTime.UtcNow)
                
                return Unauthorized(new { message = "Invalid refresh token" });

            var newAccessToken = _tokenService.GenerateAccessToken(principal.Claims);
            var newRefreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(1);
            await _context.SaveChangesAsync();

            return Ok(new { accessToken = newAccessToken, refreshToken = newRefreshToken });
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return Unauthorized(new { message = "User is not authenticated" });
            }

            var username = User.Identity.Name;
            var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == username);

            if (user != null)
            {
                user.RefreshToken = null;
                user.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(1);  // Optional: Clear expiry time as well
                await _context.SaveChangesAsync();
            }

            return Ok(new { message = "Logged out successfully" });
        }
    }
}
