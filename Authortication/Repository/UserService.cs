using Authortication.Data;
using Authortication.Models;
using Microsoft.AspNetCore.Identity;

namespace Authortication.Repository
{
    public class UserService : IUserService
    {
        private readonly AppDataContext _appData;
        private readonly UserManager<ApplicationUser> _userManager;

        public UserService(AppDataContext appData,UserManager<ApplicationUser> userManager)
        {
            _appData = appData;
            _userManager = userManager;
        }
    }
}
