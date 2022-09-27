using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using VerifyEmailForgotPassword.Service;

namespace VerifyEmailForgotPassword.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly DataContext _context;
        private readonly IUserService _userService;

        public UserController(DataContext context, IUserService userService)
        {
            _context = context;
            _userService = userService;
        }

        [HttpPost("register")]
        public IActionResult Register(UserRegisterRequest request)
        {
            var response = _userService.Register(request);
            if (string.IsNullOrEmpty(response))
                return BadRequest("User already exists.");
            return Ok(response);
        }

        [HttpPost("login")]
        public IActionResult Login(UserLoginRequest request)
        {
            var response = _userService.Login(request);

            if (string.IsNullOrEmpty(response))
                return BadRequest("Something wrong.");
            return Ok(response);
        }

        [HttpPost("verify")]
        public IActionResult Verify(string token)
        {
            var response = _userService.Verify(token);
            if (string.IsNullOrEmpty(response))
                return BadRequest("User");
            return Ok(response);
        }

        [HttpPost("forgot-password")]
        public IActionResult ForgotPassword(string email)
        {
            var response = _userService.ForgotPassword(email);
            if (string.IsNullOrEmpty(response))
                return BadRequest("User not found.");
            return Ok(response);
        }

        [HttpPost("reset-password")]
        public IActionResult ResetPassword(ResetPasswordRequest request)
        {
            var response = _userService.ResetPassword(request);
            if (string.IsNullOrEmpty(response))
                return BadRequest("Invalid Token.");
            return Ok(response);
        }
    }
}
