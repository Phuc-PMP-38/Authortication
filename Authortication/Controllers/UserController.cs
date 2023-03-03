using Authortication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Authortication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public UserController(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }
        [Authorize(Roles = "User,Admin")]
        [HttpGet("GetUser")]
        public async Task<IActionResult> GetDataUser()
        {
            return Ok(await _userManager.Users.ToListAsync());
        }
        [Authorize(Roles = "Admin")]
        [HttpDelete("DeleteUser")]
        public async Task<IActionResult> DeleteUser(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return BadRequest("Không có đối tượng ");
            }
            await _userManager.DeleteAsync(user);
            return Ok(await _userManager.Users.ToListAsync());
        }
    }
}
