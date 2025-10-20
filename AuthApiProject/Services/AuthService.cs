using AuthApiProject.Data;
using AuthApiProject.DTOs;
using AuthApiProject.Helpers;
using AuthApiProject.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace AuthApiProject.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AppDbContext _context;
        private readonly IConfiguration _config;
        private readonly IEmailService _emailService;

        public AuthService(UserManager<ApplicationUser> userManager, AppDbContext context, IConfiguration config, IEmailService emailService)
        {
            _userManager = userManager;
            _context = context;
            _config = config;
            _emailService = emailService;
        }

        public async Task RegisterAsync(RegisterDto dto)
        {
            var userExists = await _userManager.FindByEmailAsync(dto.Email);
            if (userExists != null)
                throw new ApplicationException("User already exists.");

            var user = new ApplicationUser
            {
                UserName = dto.Email,
                Email = dto.Email,
                FullName = dto.FullName
            };

            var result = await _userManager.CreateAsync(user, dto.Password);
            if (!result.Succeeded)
                throw new ApplicationException(String.Join(" | ", result.Errors.Select(e => e.Description)));

            await _userManager.AddToRoleAsync(user, "User");
        }

        public async Task<TokenResponseDto> LoginAsync(LoginDto dto, string ipAddress)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, dto.Password))
                throw new ApplicationException("Invalid credentials");

            var roles = await _userManager.GetRolesAsync(user);

            // generate token
            var jwtToken = JwtHelper.CreateJwtToken(user, roles, _config);
            var accessToken = JwtHelper.WriteToken(jwtToken);

            // generate refresh token
            var refreshToken = GenerateRefreshToken(ipAddress);
            user.RefreshTokens ??= new List<RefreshToken>();
            user.RefreshTokens.Add(refreshToken);

            // remove old inactive refresh tokens (optional cleanup)
            _context.RefreshTokens.RemoveRange(user.RefreshTokens.Where(rt => !rt.IsActive));
            await _context.SaveChangesAsync();

            return new TokenResponseDto
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken.Token
            };
        }

        public async Task<TokenResponseDto> RefreshTokenAsync(RefreshTokenRequestDto dto, string ipAddress)
        {
            var user = await _context.Users
                        .Include(u => u.RefreshTokens)
                        .SingleOrDefaultAsync(u => u.RefreshTokens
                        .Any(t => t.Token == dto.RefreshToken));

            if (user == null)
                throw new ApplicationException("Invalid refresh token");

            var refreshToken = user.RefreshTokens.First(t => t.Token == dto.RefreshToken);

            if (!refreshToken.IsActive)
                throw new ApplicationException("Invalid refresh token");


            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAddress;

            // new refresh token
            var newRefreshToken = GenerateRefreshToken(ipAddress);
            refreshToken.ReplacedByToken = newRefreshToken.Token;
            user.RefreshTokens.Add(newRefreshToken);

            // new JWT access token
            var roles = await _userManager.GetRolesAsync(user);
            var jwtToken = JwtHelper.CreateJwtToken(user, roles, _config);
            var accessToken = JwtHelper.WriteToken(jwtToken);

            await _context.SaveChangesAsync();

            return new TokenResponseDto
            {
                AccessToken = accessToken,
                RefreshToken = newRefreshToken.Token
            };
        }

        public async Task ForgotPasswordAsync(ForgotPasswordDto dto, string origin)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
                return; 

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetUrl = $"{origin}/reset-password?email={dto.Email}&token={Uri.EscapeDataString(token)}";

            var emailHtml = $"<p>Please reset your password by clicking <a href=\"{resetUrl}\">here</a>.</p>";
            await _emailService.SendEmailAsync(dto.Email, "Reset Password", emailHtml);
        }

        public async Task ResetPasswordAsync(ResetPasswordDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
                throw new ApplicationException("User not found");

            var result = await _userManager.ResetPasswordAsync(user, dto.Token, dto.NewPassword);
            if (!result.Succeeded)
                throw new ApplicationException(String.Join(" | ", result.Errors.Select(e => e.Description)));

            // optionally revoke all refresh tokens to force login again
            user.RefreshTokens.ToList().ForEach(rt => {
                if (rt.IsActive)
                {
                    rt.Revoked = DateTime.UtcNow;
                    rt.RevokedByIp = "PasswordChanged";
                }
            });
            await _context.SaveChangesAsync();
        }

        public async Task ChangePasswordAsync(string userId, ChangePasswordDto dto)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                throw new ApplicationException("User not found");

            var result = await _userManager.ChangePasswordAsync(user, dto.CurrentPassword, dto.NewPassword);
            if (!result.Succeeded)
                throw new ApplicationException(String.Join(" | ", result.Errors.Select(e => e.Description)));

            user.RefreshTokens.ToList().ForEach(rt => {
                if (rt.IsActive)
                {
                    rt.Revoked = DateTime.UtcNow;
                    rt.RevokedByIp = "PasswordChanged";
                }
            });
            await _context.SaveChangesAsync();
        }

        // generate refresh token
        private RefreshToken GenerateRefreshToken(string ipAddress)
        {
            return new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.UtcNow.AddDays(double.Parse(_config["Jwt:RefreshTokenExpiryDays"]!)),
                Created = DateTime.UtcNow,
                CreatedByIp = ipAddress
            };
        }

    }
}
