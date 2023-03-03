using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Authortication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class RoleController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;

        public RoleController(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }
        [Authorize(Roles = "User,Admin")]
        [HttpGet]
        public async Task<IActionResult> GetRole()
        {
            return Ok(await _roleManager.Roles.ToListAsync());
        }
        [Authorize(Roles = "Admin")]
        [HttpGet("RoleID")]
        public async Task<IActionResult> GetRoleId(string roleId)
        {
            return Ok(await _roleManager.Roles.FirstOrDefaultAsync(e=>e.Id == roleId));
        }
        [Authorize(Roles = "Admin")]
        [HttpPut]
        public async Task<IActionResult> UpdateRole([FromBody]IdentityRole role)
        {
            var resutl = await _roleManager.Roles.FirstOrDefaultAsync(e => e.Id == role.Id);
            if(resutl == null)
            {
                return BadRequest("Không tìm thấy đối tượng");
            }
            IdentityRole Irole = new IdentityRole
            {
                Id = role.Id,
                Name = role.Name,
                NormalizedName = role.NormalizedName,
            };
            var resultup = await _roleManager.UpdateAsync(Irole);
            if (resultup.Succeeded)
            {
                return Ok(resutl);
            }
            return BadRequest("Không tìm thấy đối tượng");
        }
        [Authorize(Roles = "Admin")]
        [HttpDelete]
        public async Task<IActionResult> DeleteRole(string id)
        {
            var user = await _roleManager.FindByIdAsync(id);
            if (user == null)
            {
                return BadRequest("Không có đối tượng ");
            }
            await _roleManager.DeleteAsync(user);
            return Ok(await _roleManager.Roles.ToListAsync());
        }
    }
}
