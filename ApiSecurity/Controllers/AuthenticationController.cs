using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ApiSecurity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IConfiguration configuration;

        public AuthenticationController(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        public record AuthenicationData(string? UserName, string? Password);  
        public record UserData(int UserId, string UserName);

        // api/authentication/token
        [HttpPost("token")]
        public ActionResult<string> Authenticate([FromBody] AuthenicationData data)
        {
            var user = ValidateCredentials(data);

            if (user is null)
            {
                return Unauthorized();
            }

            var token = GenerateToken(user);
            return Ok(token);

        }


        private string GenerateToken(UserData userData)
        {
            var secretKey = new SymmetricSecurityKey(
                Encoding.ASCII.GetBytes(
                    this.configuration.GetValue<string>("Authentication:SecretKey")));

            var signingCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);

            List<Claim> claims = new ();
            claims.Add(new(JwtRegisteredClaimNames.Sub, userData.UserId.ToString()));
            claims.Add(new(JwtRegisteredClaimNames.UniqueName, userData.UserName));

            var token = new JwtSecurityToken(
                this.configuration.GetValue<string>("Authentication:Issuer"),
                this.configuration.GetValue<string>("Authentication:Audience"),
                claims,
                DateTime.UtcNow, // When this token becomes available 
                DateTime.UtcNow.AddMinutes(1), // this is when token expires
                signingCredentials);
                
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private UserData? ValidateCredentials(AuthenicationData data)
        {
            // This is not production code. only for demo
            if (CompareValues(data.UserName, "esan") && 
                CompareValues(data.Password, "Test123" ))
            {
                return new UserData(1, data.UserName!);
            }

            if (CompareValues(data.UserName, "sam") &&
               CompareValues(data.Password, "Test123"))
            {
                return new UserData(2, data.UserName!);
            }

            return null;
        }


        private bool CompareValues(string? actual, string? expected)
        {
            if (actual is not null) 
            {
                if (actual.Equals(expected))
                {
                    return true;
                }
            }
            return false;
        }
    }
}
