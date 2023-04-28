using Login_SignUpPage_Backend.Context;
using Login_SignUpPage_Backend.Helpers;
using Login_SignUpPage_Backend.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;

namespace Login_SignUpPage_Backend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;

        public UserController(AppDbContext appDbContext)
        {
            _authContext = appDbContext;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();

            var user = await _authContext.Users
                .FirstOrDefaultAsync(x => x.Username == userObj.Username);

            if (user == null)
                return NotFound( new { Message = "User Not Found !" });

           if (!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
            {
                return BadRequest(new { Message = "Password is Incorect !" });
            }


            user.Token = CreateJwt(user);

                return Ok ( new {
                    Token = user.Token,
                    Message = "Login Success !" 
                });
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();

            // Check Username
            if (await CheckUserNameExistAsync(userObj.Username))
                return BadRequest(new { Message = " Username Already Exist !"});

            // Check Email
            if (await CheckEmailExistAsync(userObj.Email))
                return BadRequest(new { Message = "Email Already exist!" });

            // CheckPasswordStrength

            var pass = CkeckPasswordStrength(userObj.Password);
            if (!string.IsNullOrEmpty(pass))
                return BadRequest(new { Message = pass.ToString() });

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = "NULL";
            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();

            return Ok( new { Message = "User Registered!" });
        }

        private Task<bool> CheckUserNameExistAsync(string username)
        => _authContext.Users.AnyAsync(x => x.Username == username);

        private Task<bool> CheckEmailExistAsync(string mail)
        => _authContext.Users.AnyAsync(x => x.Email == mail);

        private string CkeckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();
            if(password.Length<8)
                sb.Append("Minim password length should be 8 ." + Environment.NewLine);
            if(!(Regex.IsMatch(password,"[a-z]") && Regex.IsMatch(password,"[A-Z]") && Regex.IsMatch(password,"[0-9]")))
                sb.Append( "Password should be Alphanumeric "+ Environment.NewLine);
            if (!(Regex.IsMatch(password, "[<,>,@,!,#,$,%,^,&,*,(,),_,+,\\[,\\],{,},?,:,;,|,,',\\,.,/,~,`,-,=]")))
                sb.Append("Password should contain special chars" + Environment.NewLine);
            return sb.ToString();
        }

        private string CreateJwt(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("veryverysecret...");
            var identity = new ClaimsIdentity(new Claim[] {
             new Claim(ClaimTypes.Role,user.Role),
             new Claim(ClaimTypes.Name,$"{user.FirstName} {user.LastName}")
        });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);                       // este utilizata pentru a semna token-ul
            var tokenDescriptor = new SecurityTokenDescriptor 
            {
                Subject = identity,
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = credentials
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);                                                                    // se creaza un token
            return jwtTokenHandler.WriteToken(token);                                                                                    // se scrie un token
        } 

        [HttpGet("users")]
        public async Task<ActionResult<IEnumerable<User>>> GetAllUsers()
        {
            return Ok(await _authContext.Users.ToListAsync());
        }
    }
}
