namespace Aurelyn.Domain.Models.User
{
    public class UserLookup
    {
        public int UserId { get; set; }
        public int TenantId { get; set; }
        public string Email { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public int ReturnValue { get; set; }
    }
}
