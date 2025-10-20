using AuthApiProject.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AuthApiProject.Controllers
{
    [Authorize(Roles = "Admin")]
    [Route("api/[controller]")]
    [ApiController]
    public class AdminController : ControllerBase
    {
        private readonly ILogger<AdminController> _logger;
        private readonly UserManager<ApplicationUser> _userManager;

        public AdminController(ILogger<AdminController> logger, UserManager<ApplicationUser> userManager)
        {
            _logger = logger;
            _userManager = userManager;
        }


        [HttpGet("GetAllUser")]
        public IActionResult GetAllUsers()
        {
            var users = _userManager.Users
                .Select(u => new
                {
                    u.Id,
                    u.FullName,
                    u.Email,
                    u.UserName,
                    u.EmailConfirmed
                })
                .ToList();

            var currentUserEmail = User.FindFirstValue(ClaimTypes.Email);
            var currentUserName = User.FindFirstValue(ClaimTypes.Name);

            return Ok(new
            {
                Message = $"Hello Admin {currentUserName} ({currentUserEmail})! Here are all registered users.",
                Users = users
            });
        }



    }
}
