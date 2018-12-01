using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using Web.Auth.Security.Models;

namespace Web.Auth.Security
{
    public class JwtAuthorization
    {
        public static void ConfigureClient(IServiceCollection services, JwtIssuerOptions issuerOptions)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = issuerOptions.Issuer,

                ValidateAudience = true,
                ValidAudience = issuerOptions.Audience,

                ValidateIssuerSigningKey = true,
                IssuerSigningKey = issuerOptions.SignKey,

                RequireExpirationTime = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(configureOptions =>
            {
                configureOptions.ClaimsIssuer = issuerOptions.Issuer;
                configureOptions.TokenValidationParameters = tokenValidationParameters;
                configureOptions.SaveToken = true;
            });

            services.AddAuthorization(options =>
            {
                options.AddPolicy("ApiUser", policy => policy.RequireClaim("api", "api_access"));
            });
        }
    }
}