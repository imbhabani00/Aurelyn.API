using Microsoft.AspNetCore.Http;

namespace Aurelyn.Application.Dtos.Request.User
{
    public class ProfilePictureUploadRequest
    {
        public IFormFile? File { get; set; }
    }
}