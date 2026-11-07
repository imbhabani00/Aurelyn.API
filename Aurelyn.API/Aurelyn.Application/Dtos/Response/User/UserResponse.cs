namespace Aurelyn.Application.Dtos.Response.User
{
    public class UserResponse
    {
        public int UserId { get; set; }
        public string Email { get; set; }
        public int RoleId { get; set; }
        public string RoleName { get; set; } 
        public string RoleCode { get; set; }
        public int TenantId { get; set; }
        public bool IsActive { get; set; } = true;
        public string? RefreshToken { get; set; }
        public string? CreatedBy { get; set; }
        public string? ModifiedBy { get; set; }
        public string? DeletedBy { get; set; }
        public string PhoneNumber { get; set; }
        public string PasswordHash { get; set; }
        public DateTime? PasswordChangedDate { get; set; }
        public DateTime? RefreshTokenExpiry { get; set; }
        public DateTime? CreatedDate { get; set; }
        public DateTime? UpdatedDate { get; set; }
        public DateTime? LastLoginDate { get; set; }
        public DateTime? ModifiedDate { get; set; }
        public DateTime? DeletedDate { get; set; }
    }

    public class AuthenticateResultResponse
    {
        public UserResponse AuthunticateUser { get; set; }
        public int ReturnValue { get; set; }
    }
}