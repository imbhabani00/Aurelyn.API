namespace Aurelyn.Application.Dtos.Response.OtpResponse
{
    public class OtpResponse
    {
        public long OtpId { get; set; }
        public int TenantId { get; set; }
        public int UserId { get; set; }
        public string Purpose { get; set; } = string.Empty;
        public string ClientApp { get; set; } = string.Empty;
        public string CodeHash { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }
        public int Attempts { get; set; }
        public DateTime? UsedAt { get; set; }
        public string? IPAddress { get; set; }
        public DateTime CreatedDate { get; set; }
    }
}