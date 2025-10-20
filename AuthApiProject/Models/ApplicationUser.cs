using AuthApiProject.Data;
using Microsoft.AspNetCore.Identity;

namespace AuthApiProject.Models
{
    public class ApplicationUser: IdentityUser
    {
        public string? FullName { get; set; }

        public ICollection<RefreshToken>? RefreshTokens { get; set; }

    }
}
