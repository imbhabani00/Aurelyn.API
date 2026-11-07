using Aurelyn.API.Helper;
using Aurelyn.Application.Dtos.Response;
using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace Aurelyn.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class BaseController : ControllerBase
    {
        public int UserId { get; set; }
        public int TenantId { get; set; }
        public int TenantCode { get; set; }
        public int AppCode { get; set; }
        public string? RoleCode { get; set; }
        public int RoleId { get; set; }
        protected int? CurrentUserId => User.GetUserId();
        protected int? CurrentTenantId => User.GetTenantId();
        protected long? CurrentSessionId => User.GetSessionId();
        protected string? CurrentUserEmail => User.GetUserEmail();
        protected string? CurrentUserRole => User.GetUserRole();

        protected string? GetIpAddress()
        {
            return HttpContext.Connection.RemoteIpAddress?.ToString();
        }

        protected string GetUserAgent()
        {
            var userAgent = Request.Headers["User-Agent"].ToString();
            return userAgent.Length > 500 ? userAgent.Substring(0, 500) : userAgent;
        }

        protected ApiResponse BuildValidationErrorApiResponse(FluentValidation.Results.ValidationResult validateResult)
        {
            var validationErrors = new List<Application.Dtos.Response.ValidationError>();
            var errors = validateResult.Errors;

            foreach (var error in errors)
            {
                validationErrors.Add(new Application.Dtos.Response.ValidationError
                {
                    ErrorCode = error.ErrorCode,
                    ErrorMessage = error.ErrorMessage,
                    PropertyName = error.PropertyName
                });
            }

            return new ApiResponse
            {
                Response = validationErrors,
                ErrorMessage = "Validation Errors",
                StatusCode = (int)HttpStatusCode.BadRequest,
                Status = false,
                Message = "Failed"
            };
        }

        protected ApiResponse CreateSuccessResponse(object response, HttpStatusCode statusCode = HttpStatusCode.OK, string message = "Success")
        {
            return new ApiResponse
            {
                Response = response,
                ErrorMessage = "",
                StatusCode = (int)statusCode,
                Status = true,
                Message = message
            };
        }

        protected ApiResponse CreateFailedApiResponse(object response, HttpStatusCode statusCode = HttpStatusCode.BadRequest, string message = "Failed")
        {
            return new ApiResponse
            {
                Response = response,
                ErrorMessage = "",
                StatusCode = (int)statusCode,
                Status = false,
                Message = message
            };
        }
    }
}