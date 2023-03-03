using Authortication.Models;
using Microsoft.AspNetCore.Identity;

namespace Authortication.Repository
{
    public interface IAccountRepository
    {
        Task<ApiResponse> SignUpAsync(SignUpModel signUpModel);
        Task<TokenModel> LoginAsync(SignInModel signInModel);
        Task<ApiResponse> RenewToken(TokenModel model);
        Task<TokenModel> GenerateToken(SignInModel signInModel);
    }
}
