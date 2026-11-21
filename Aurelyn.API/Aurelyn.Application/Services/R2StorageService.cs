using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using Aurelyn.Domain.Settings;
using Microsoft.Extensions.Options;

namespace Aurelyn.Application.Services
{
    public interface IR2StorageService
    {
        Task UploadAsync(Stream stream, string key, string contentType);
        Task DeleteAsync(string key);
        string? GetPublicUrl(string? key);
    }
    public class R2StorageService : IR2StorageService
    {
        private readonly StorageSettings _opt;
        private readonly IAmazonS3 _s3;

        public R2StorageService(IOptions<StorageSettings> options)
        {
            _opt = options.Value;
            _s3 = new AmazonS3Client(
                new BasicAWSCredentials(_opt.R2.AccessKey, _opt.R2.SecretKey),
                new AmazonS3Config
                {
                    ServiceURL = $"https://{_opt.R2.AccountId}.r2.cloudflarestorage.com",
                    ForcePathStyle = true,
                    AuthenticationRegion = "auto"
                    // On AWSSDK.S3 >= 3.7.400 also add (R2 rejects the new default checksums):
                    // RequestChecksumCalculation = RequestChecksumCalculation.WHEN_REQUIRED,
                    // ResponseChecksumValidation = ResponseChecksumValidation.WHEN_REQUIRED
                });
        }

        public async Task UploadAsync(Stream stream, string key, string contentType)
        {
            await _s3.PutObjectAsync(new PutObjectRequest
            {
                BucketName = _opt.R2.Bucket,
                Key = key,
                InputStream = stream,
                ContentType = contentType,
                DisablePayloadSigning = true
            });
        }

        public async Task DeleteAsync(string key)
            => await _s3.DeleteObjectAsync(_opt.R2.Bucket, key);

        public string? GetPublicUrl(string? key)
            => string.IsNullOrEmpty(key) ? null : $"{_opt.PublicBaseUrl.TrimEnd('/')}/{key}";
    }
}
