namespace Aurelyn.Domain.Models.AuditLog
{
    public class AuditLog
    {
        public int TenantId { get; set; }
        public int? UserId { get; set; }
        public int? ModuleId { get; set; }
        public string ActionType { get; set; } = string.Empty;
        public string TableName { get; set; } = string.Empty;
        public string? RecordId { get; set; }
        public string? OldValues { get; set; }
        public string? NewValues { get; set; }
        public string? IPAddress { get; set; }
        public string? UserAgent { get; set; }
    }
}
