using Authortication.Data;
using Authortication.Models;
using MailKit.Net.Smtp;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MimeKit;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Authortication.Repository
{
    public class AccountRepository : IAccountRepository
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly AppDataContext _appData;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;

        public AccountRepository(UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IConfiguration configuration,
            AppDataContext appData,RoleManager<IdentityRole> roleManager
            ,IEmailService emailService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _appData = appData;
            _roleManager = roleManager;
            _emailService = emailService;
        }


        public async Task<ApiResponse> SignUpAsync(SignUpModel signUpModel)
        {
            //Check User Exist
            var userExit = await _userManager.FindByEmailAsync(signUpModel.Email);
            if (userExit != null)
            {
                return new ApiResponse { Success = false, Message= "Thís Email doesnot exit" };
            }
            //Add the Role in the database
            var roleExists = await _roleManager.RoleExistsAsync(signUpModel.Role);
            if (!roleExists)
            {
                var newRole = new IdentityRole(signUpModel.Role)
                {
                    Name = signUpModel.Role,
                    NormalizedName = signUpModel.Role.ToUpper(),
                };
                var roleCreated = await _roleManager.CreateAsync(newRole);
                var roleExistsYet = await _roleManager.RoleExistsAsync(signUpModel.Role);
                if (roleExists)
                {
                    return new ApiResponse { Success = false, Message = "Thís Roles doesnot exit" };
                }
            }
            //Add the User in the database
            var user = new ApplicationUser()
            {
                FirstName = signUpModel.FirstName,
                LastName = signUpModel.LastName,
                Email = signUpModel.Email,
                UserName = signUpModel.Email
            };
            var result = await _userManager.CreateAsync(user, signUpModel.Password);
            if (!result.Succeeded)
            {
                return new ApiResponse { Success = false, Message = "Thís Password doesnot exit" };
            }
            // Add Role to the user
            await _userManager.AddToRoleAsync(user, signUpModel.Role);

            return new ApiResponse { Success = true, Message = $"User created & email sent {user.Email} to Successfully ",Data = user};
        }

        public async Task<TokenModel> LoginAsync(SignInModel signInModel)
        {
            var result = await _signInManager.PasswordSignInAsync(signInModel.Email, signInModel.Password, false, false);

            if (!result.Succeeded)
            {
                return new TokenModel { AccessToken=null,RefreshToken=null};
            }
            var token = await GenerateToken(signInModel);
            return token;
        }

        public async Task<TokenModel> GenerateToken(SignInModel signInModel)
        {
            var result = await _userManager.Users.FirstOrDefaultAsync(e => e.Email == signInModel.Email);
            if (result == null)
            {
                return new TokenModel { AccessToken = null, RefreshToken = null };
            }
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            var secretKeyBytes = Encoding.UTF8.GetBytes(_configuration["JWT:Key"]);
            var roleUser = await _userManager.GetRolesAsync(result);

            var claims = new List<Claim>{
                    new Claim(ClaimTypes.Name, result.Email),
                    new Claim(JwtRegisteredClaimNames.Email, result.Email),
                    new Claim(JwtRegisteredClaimNames.Sub, _configuration["JWT:Subject"]),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim("UserName", result.FirstName + result.LastName),
                    new Claim("Id", result.Id.ToString()) 
            };
            foreach(var role in roleUser)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }
            //var tokenDescription = new SecurityTokenDescriptor
            //{
            //    Subject = new ClaimsIdentity(claims),
            //    Expires = DateTime.UtcNow.AddSeconds(20),
            //    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(secretKeyBytes), SecurityAlgorithms.HmacSha256)
            //};
            //var token = jwtTokenHandler.CreateToken(tokenDescription);
            //var accessToken = jwtTokenHandler.WriteToken(token);
            //var refreshToken = GenerateRefreshToken();


            var signin = new SigningCredentials(new SymmetricSecurityKey(secretKeyBytes), SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                _configuration["JWT:Issuer"],
                _configuration["JWT:Audience"],
                claims,
                expires:DateTime.Now.AddMinutes(20),
                signingCredentials:signin
                );
            var accessToken = new JwtSecurityTokenHandler().WriteToken(token);
            var refreshToken = GenerateRefreshToken();
            var refreshTokenEntity = new UserRefeshToken
            {
                Id = Guid.NewGuid(),
                JwtId = token.Id,
                UserId = result.Id,
                Token = refreshToken,
                IsUsed = false,
                IsRevoked = false,
                IssuedAt = DateTime.UtcNow,
                ExpiredAt = DateTime.UtcNow.AddHours(1)
            };

            await _appData.UserRefeshTokens.AddAsync(refreshTokenEntity);
            await _appData.SaveChangesAsync();
            var TokenTime = new TokenModel
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };
            return TokenTime;
        }
        private string GenerateRefreshToken()
        {
            var random = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(random);

                return Convert.ToBase64String(random);
            }
        }
        public async Task<ApiResponse> RenewToken(TokenModel model)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var secretKeyBytes = Encoding.UTF8.GetBytes(_configuration["JWT:Key"]);
            var tokenValidateParam = new TokenValidationParameters
            {
                //tự cấp token
                ValidateIssuer = false,
                ValidateAudience = false,

                //ký vào token
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(secretKeyBytes),

                ClockSkew = TimeSpan.Zero,

                ValidateLifetime = false //ko kiểm tra token hết hạn
            };
            try
            {
                //check 1: AccessToken valid format
                var tokenInVerification = jwtTokenHandler.ValidateToken(model.AccessToken, tokenValidateParam, out var validatedToken);

                //check 2: Check alg
                if (validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);
                    if (!result)//false
                    {
                        return new ApiResponse
                        {
                            Success = false,
                            Message = "Invalid token"
                        };
                    }
                }

                //check 3: Check accessToken expire?
                var utcExpireDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);

                var expireDate = ConvertUnixTimeToDateTime(utcExpireDate);
                if (expireDate > DateTime.UtcNow)
                {
                    return new ApiResponse
                    {
                        Success = false,
                        Message = "Access token has not yet expired"
                    };
                }

                //check 4: Check refreshtoken exist in DB
                var storedToken = _appData.UserRefeshTokens.FirstOrDefault(x => x.Token == model.RefreshToken);
                if (storedToken == null)
                {
                    return new ApiResponse
                    {
                        Success = false,
                        Message = "Refresh token does not exist"
                    };
                }

                //check 5: check refreshToken is used/revoked?
                if (storedToken.IsUsed)
                {
                    return new ApiResponse
                    {
                        Success = false,
                        Message = "Refresh token has been used"
                    };
                }
                if (storedToken.IsRevoked)
                {
                    return new ApiResponse
                    {
                        Success = false,
                        Message = "Refresh token has been revoked"
                    };
                }

                //check 6: AccessToken id == JwtId in RefreshToken
                var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
                if (storedToken.JwtId != jti)
                {
                    return new ApiResponse
                    {
                        Success = false,
                        Message = "Token doesn't match"
                    };
                }

                //Update token is used
                storedToken.IsRevoked = true;
                storedToken.IsUsed = true;
                _appData.Update(storedToken);
                await _appData.SaveChangesAsync();

                //create new token
                var user = await _userManager.Users.FirstOrDefaultAsync(nd => nd.Id == storedToken.UserId);
                if(user==null)
                {
                    return null;
                }
                SignInModel sign = new SignInModel
                {
                    Email = user.Email
                };

                var token = await GenerateToken(sign);

                return new ApiResponse
                {
                    Success = true,
                    Message = "Renew token success",
                    Data = token
                };
            }
            catch (Exception ex)
            {
                return new ApiResponse
                {
                    Success = false,
                    Message = "Something went wrong"
                };
            }
        }
        private DateTime ConvertUnixTimeToDateTime(long utcExpireDate)
        {
            var dateTimeInterval = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTimeInterval.AddSeconds(utcExpireDate).ToUniversalTime();

            return dateTimeInterval;
        }
    }
}
