using Authortication.Models;
using Authortication.Repository;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Authortication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SendMailController : ControllerBase
    {
        private readonly IEmailService _emailService;

        public SendMailController(IEmailService emailService)
        {
            _emailService = emailService;
        }
        [HttpGet("Mail")]
        public async Task<IActionResult> CheckToken()
        {
            _emailService.TestEmail();
            return StatusCode(StatusCodes.Status200OK,new Responses { Status = "Success",Message = "Email sent SuccessFully"});
        }
        [HttpPost("ConfirmEmails")]
        public async Task<IActionResult> ConfirmEmails()
        {
            _emailService.TestEmail();
            return StatusCode(StatusCodes.Status200OK, new Responses { Status = "Success", Message = "Email sent SuccessFully" });
        }
    }
}
