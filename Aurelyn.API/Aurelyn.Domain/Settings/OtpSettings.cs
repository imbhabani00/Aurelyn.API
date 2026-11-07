namespace Aurelyn.Domain.Settings
{
    public class OtpSettings
    {
        public int ExpiryMinutes { get; set; }
        public int MaxAttempts { get; set; }
        public int ResendCooldownSeconds { get; set; }
        public int MaxResendsPerHour { get; set; }
    }
}
