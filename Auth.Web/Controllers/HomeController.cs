using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Web.Auth.Data;
using Web.Auth.Models;
using Web.Auth.Security.Models;

namespace Web.Auth.Controllers
{
    public class HomeController : Controller
    {
        private UserManager<ApplicationUser> userManager;
        private readonly JwtIssuerOptions options;

        public HomeController(UserManager<ApplicationUser> userManager, IOptions<JwtIssuerOptions> options)
        {
            this.userManager = userManager;
            this.options = options.Value;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult About()
        {
            ViewData["Message"] = "Your application description page.";

            return View();
        }

        [Authorize]
        public IActionResult Contact()
        {
            ViewData["Message"] = "Your contact page.";

            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [Authorize]
        public async System.Threading.Tasks.Task<IActionResult> TokenAsync()
        {
            var user = HttpContext.User;

            var currentUser = await userManager.FindByNameAsync(user.Identity.Name);

            if (currentUser != null)
            {
                var claims = new[] {
                    new Claim(JwtRegisteredClaimNames.Sub,currentUser.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
                };

                var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secretKey"));

                var token = new JwtSecurityToken(
                   issuer: options.Issuer,
                   audience: options.Audience,
                   signingCredentials: options.SigningCredentials);

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token)
                });
            }

            return Unauthorized();
        }
    }
}