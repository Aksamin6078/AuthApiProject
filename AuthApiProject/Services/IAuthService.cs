using AuthApiProject.DTOs;

namespace AuthApiProject.Services
{
    public interface IAuthService
    {

        Task RegisterAsync(RegisterDto dto);
        Task<TokenResponseDto> LoginAsync(LoginDto dto, string ipAddress);
        Task<TokenResponseDto> RefreshTokenAsync(RefreshTokenRequestDto dto, string ipAddress);
        Task ForgotPasswordAsync(ForgotPasswordDto dto, string origin);
        Task ResetPasswordAsync(ResetPasswordDto dto);
        Task ChangePasswordAsync(string userId, ChangePasswordDto dto);

    }
}
