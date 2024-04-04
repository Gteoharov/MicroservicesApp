using System.Security.Claims;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using IdentityModel;
using IdentityService.Models;
using Microsoft.AspNetCore.Identity;

namespace IdentityService;

public class CustomProfileService : IProfileService
{
    private readonly UserManager<ApplicationUser> _userManager;

    public CustomProfileService(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task GetProfileDataAsync(ProfileDataRequestContext context)
    {
        var user = await _userManager.GetUserAsync(context.Subject);
        if (user != null)
        {
            var existingClaims = await _userManager.GetClaimsAsync(user);
            var claims = new List<Claim>();

            if (user.UserName != null)
            {
                claims.Add(new Claim("username", user.UserName));
            }
            else
            {
                // Handle the case where user.UserName is null, e.g., log a warning, throw an exception, or use a default value.
                claims.Add(new Claim("username", "default"));
            }

            context.IssuedClaims.AddRange(claims);

            var nameClaim = existingClaims.FirstOrDefault(x => x.Type == JwtClaimTypes.Name) ?? throw new ArgumentException("Claimed must be not null");
            context.IssuedClaims.Add(nameClaim);
        }
    }

    public Task IsActiveAsync(IsActiveContext context)
    {
        return Task.CompletedTask;
    }
}