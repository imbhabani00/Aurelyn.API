namespace Aurelyn.Application.Dtos.Response.Session
{
    public class UserSessionResponse
    {
        public long SessionId { get; set; }
        public int UserId { get; set; }
        public int TenantId { get; set; }
        public DateTime ExpiresAt { get; set; }
        public DateTime? RevokedAt { get; set; }
        public string? DeviceInfo { get; set; }
        public string? IPAddress { get; set; }
        public DateTime CreatedDate { get; set; }
        public DateTime? LastUsedDate { get; set; }
        public int ReturnValue { get; set; }
    }
}