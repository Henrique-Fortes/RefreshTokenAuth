using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using RefreshTokenAuth.Models;
using RefreshTokenAuth.Repositories;
using RefreshTokenAuth.Services;
using System.Threading.Tasks;

namespace RefreshTokenAuth.Controllers
{
    [ApiController]
    public class LoginController : ControllerBase
    {
        [HttpPost]
        [Route("login")]
        public async Task<ActionResult<dynamic>> Authenticate([FromBody] User model)
        {
            var user = UserRepository.Get(model.Username, model.Password);

            if (user == null)
                return NotFound(new { message = "Usuario ou senha invalidos" });

            var token = TokenService.GenerateToken(user);
            var refreshToken = TokenService.GenerateRefreshToken(); //gera o token novo
            TokenService.SaveRefreshToken(user.Username, refreshToken); //salva o token novo

            user.Password = "";
            return new
            {
                user = user,
                token = token,
                refreshToken = refreshToken
            };
        }

        [HttpPost]
        [Route("refresh")]
        public IActionResult Refresh(string token, string refreshToken)
        {
            var principal = TokenService.GetPrincipalFromExpiredToken(token);
            var username = principal.Identity.Name; 
            var savedRefreshToken = TokenService.GetRefreshToken(username);
            if (savedRefreshToken != refreshToken)
                throw new SecurityTokenException("Invalid refresh token");

            var newJwtToken = TokenService.GenerateToken(principal.Claims);
            var newRefreshToken = TokenService.GenerateRefreshToken();
            TokenService.DeleteRefreshToken(username, refreshToken); //Deleta o refreshToken
            TokenService.SaveRefreshToken(username, newRefreshToken); //Salva o novo Token

            return new ObjectResult(new //envia os dois para tela
            {
                token = newJwtToken,
                refreshToken = newRefreshToken
            });

            
        }
    }
}
