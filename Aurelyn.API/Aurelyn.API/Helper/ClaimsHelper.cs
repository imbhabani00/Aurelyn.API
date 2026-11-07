using System.Security.Claims;

namespace Aurelyn.API.Helper
{
    public static class ClaimsHelper
    {
        public static int? GetUserId(this ClaimsPrincipal user)
        {
            var claim = user.FindFirst(ClaimTypes.NameIdentifier);
            if (claim != null && int.TryParse(claim.Value, out var id))
                return id;
            return null;
        }

        public static int? GetTenantId(this ClaimsPrincipal user)
        {
            var tenantId = user.FindFirst("TenantId")?.Value;
            return int.TryParse(tenantId, out var id) ? id : null;
        }

        public static string? GetUserEmail(this ClaimsPrincipal user)
            => user.FindFirst(ClaimTypes.Email)?.Value;

        public static string? GetUserRole(this ClaimsPrincipal user)
            => user.FindFirst(ClaimTypes.Role)?.Value;

        public static long? GetSessionId(this ClaimsPrincipal user)
        {
            var sessionId = user.FindFirst("SessionId")?.Value;
            return long.TryParse(sessionId, out var id) ? id : null;
        }

        public static string GetClientApp(this ClaimsPrincipal user)
            => user.FindFirst("ClientApp")?.Value ?? "Web";
    }
}