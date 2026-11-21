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
        public string? MiddleName { get; set; }
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
        public string Initials { get; set; }
        public string FullName { get; set; }
        public string Country { get; set; }
        public string ZipCode { get; set; }
        public string State { get; set; }
        public string City { get; set; }
        public string? AddressLine2 { get; set; }
        public string AddressLine1 { get; set; }
        public string ProfilePictureKey { get; set; }
        public string? ProfilePictureUrl { get; set; }
    }

    public class AuthenticateResultResponse
    {
        public UserResponse AuthunticateUser { get; set; }
        public int ReturnValue { get; set; }
    }
}