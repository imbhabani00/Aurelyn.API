namespace Aurelyn.Domain.Settings
{
    public class StorageSettings
    {
        public string Provider { get; set; } = "R2";
        public string PublicBaseUrl { get; set; } = "";
        public R2Settings R2 { get; set; } = new();
    }

    public class R2Settings
    {
        public string AccountId { get; set; } = "";
        public string AccessKey { get; set; } = "";
        public string SecretKey { get; set; } = "";
        public string Bucket { get; set; } = "";
    }
}
