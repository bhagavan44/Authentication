using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Web.Auth.Security.Models
{
    public class JwtIssuerOptions
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public string SecretKey { get; set; }
        public SymmetricSecurityKey SignKey { get { return new SymmetricSecurityKey(Encoding.ASCII.GetBytes(SecretKey)); } }
        public SigningCredentials SigningCredentials => new SigningCredentials(SignKey, SecurityAlgorithms.HmacSha256);
    }
}