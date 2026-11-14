namespace Aurelyn.Application.Dtos.Response.User
{
    public class UserResponse
    {
        public int UserId { get; set; }
        public int TenantId { get; set; }
        public int RoleId { get; set; }
        public string RoleName { get; set; }
        public string RoleCode { get; set; }
        public string FirstName { get; set; }
        public string MiddleName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string PhoneNumber { get; set; }
        public string AccountStatus { get; set; }
        public bool EmailVerified { get; set; }
        public bool PhoneVerified { get; set; }
        public bool IsActive { get; set; }
        public DateTime LastLoginDate { get; set; }
        public int FailedLoginAttempts { get; set; }
        public DateTime LockedUntil { get; set; }
        public DateTime CreatedDate { get; set; }
        public string PasswordHash { get; set; }
    }

    public class AuthenticateResultResponse
    {
        public UserResponse AuthunticateUser { get; set; }
        public int ReturnValue { get; set; }
    }
}