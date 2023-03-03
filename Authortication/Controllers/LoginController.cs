using Authortication.Models;
using Authortication.Repository;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Authortication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly IAccountRepository _accountRepository;
        private readonly IEmailService _emailService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public LoginController(IAccountRepository accountRepository,IEmailService emailService,
            UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _accountRepository = accountRepository;
            _emailService = emailService;
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        [HttpPost("signup")]
        public async Task<IActionResult> SignUp([FromBody] SignUpModel signUpModel)
        {
            var result = await _accountRepository.SignUpAsync(signUpModel);
            try 
            {
                if (result.Data != null)
                {
                    ApplicationUser user = (ApplicationUser)result.Data;
                    // Add Token to Verify the email
                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

                    var configmationLink = $"{Request.Scheme}://{Request.Host}{Request.PathBase}/api/Login/ConfirmEmail?token={token}&email={user.Email}";
                    var message = new Message(new string[] { user.Email }, "Confirmation email link", configmationLink);
                    _emailService.SendEmail(message);
                }
                return StatusCode(StatusCodes.Status200OK, new Responses
                { Status = "Success", Message = result.Message });
            }
            catch(Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Responses
                { Status = "Error", Message = result.Message });
            }
        }
        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var token1 = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
                var result = await _userManager.ConfirmEmailAsync(user, token1);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK, new Responses
                    { Status = "Success", Message = $"Email Verified Successfully" });
                }
            }
            return StatusCode(StatusCodes.Status500InternalServerError, new Responses
            { Status = "Error", Message = "Thís User Doesnot exits!" });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] SignInModel signInModel)
        {
            var result = await _accountRepository.LoginAsync(signInModel);

            if (string.IsNullOrEmpty(result.RefreshToken)&& string.IsNullOrEmpty(result.AccessToken))
            {
                return Unauthorized();
            }

            return Ok(result);
        }
        [HttpPost("kttoken")]
        public async Task<IActionResult> CheckToken([FromBody] TokenModel token)
        {
            var result = await _accountRepository.RenewToken(token);
            return Ok(result);
        }
    }
}
