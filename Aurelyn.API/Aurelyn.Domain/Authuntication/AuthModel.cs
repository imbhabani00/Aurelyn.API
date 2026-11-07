namespace Aurelyn.Domain.Authuntication
{
    public class AuthModel
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string? TenantCode { get; set; }
        public string? ClientApp { get; set; }
    }

    public class LogoutModel
    {
        public string RefreshToken { get; set; } = string.Empty;
    }

    public class ChangePasswordModel
    {
        public string CurrentPassword { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public class LoginFailureResult
    {
        public int FailedLoginAttempts { get; set; }
        public DateTime? LockedUntil { get; set; }
        public int ReturnValue { get; set; }
    }
}