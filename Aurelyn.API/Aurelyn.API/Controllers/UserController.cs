using Asp.Versioning;
using Aurelyn.Application.Dtos.Request.User;
using Aurelyn.Application.Dtos.Response;
using Aurelyn.Application.Services;
using Aurelyn.Domain.Models.AuditLog;
using Aurelyn.Domain.Models.Authuntication;
using Aurelyn.Domain.Models.User;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace Aurelyn.API.Controllers
{
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v{version:apiVersion}/[controller]")]
    public class UserController : BaseController
    {
        #region Properties
        private readonly IUserService _userService;
        private readonly ILogger<UserController> _logger;
        #endregion

        #region Constructor
        public UserController(
            IUserService userService,
            ILogger<UserController> logger)
        {
            _userService = userService;
            _logger = logger;
        }
        #endregion

        #region GetProfile
        [HttpGet("me")]
        [Authorize]
        public async Task<IActionResult> GetProfile()
        {
            var apiResponse = new ApiResponse();
            try
            {
                var userId = CurrentUserId ?? 0;
                var tenantId = CurrentTenantId ?? 0;
                if (userId <= 0 || tenantId <= 0)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "Invalid access token");
                    return new ObjectResult(apiResponse);
                }

                var user = await _userService.GetByIdAsync(userId, tenantId);
                if (user == null)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.NotFound, "User not found or inactive.");
                    return new ObjectResult(apiResponse);
                }

                apiResponse = CreateSuccessApiResponse(user);
                return new ObjectResult(apiResponse);
            }
            catch (Exception ex)
            {
                apiResponse = CreateFailedApiResponse("", HttpStatusCode.InternalServerError, "An error occurred while processing your request");
                _logger.LogError(ex, "GetProfile: Error occurred while fetching user profile");
                return new ObjectResult(apiResponse);
            }
        }
        #endregion

        #region ChangePassword
        [HttpPost("change-password")]
        [Authorize]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordModel model)
        {
            var apiResponse = new ApiResponse();
            try
            {
                if (model == null
                    || string.IsNullOrWhiteSpace(model.CurrentPassword)
                    || string.IsNullOrWhiteSpace(model.NewPassword))
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.BadRequest, "Current password and new password are required.");
                    return new ObjectResult(apiResponse);
                }

                if (model.NewPassword != model.ConfirmPassword)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.BadRequest, "New password and confirm password do not match.");
                    return new ObjectResult(apiResponse);
                }

                var userId = CurrentUserId ?? 0;
                var tenantId = CurrentTenantId ?? 0;
                if (userId <= 0 || tenantId <= 0)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "Invalid access token");
                    return new ObjectResult(apiResponse);
                }

                // the current session stays signed in, every other session is revoked
                long? currentSessionId = CurrentSessionId;

                var resetPasswordDetails = new ResetPassword()
                {
                    UserId = userId,
                    TenantId = tenantId,
                    CurrentPassword = model.CurrentPassword,
                    NewPassword = model.NewPassword,
                    CurrentSessionId = model.CurrentSessionId
                };
                var result = await _userService.ChangePasswordAsync(resetPasswordDetails);

                switch (result.ReturnValue)
                {
                    case 0:
                        await WriteAuditAsync(tenantId, userId, "UPDATE", "tbl_Users", userId.ToString(), "Password changed, other sessions revoked");
                        _logger.LogInformation("ChangePassword: Password changed - UserId: {UserId}", userId);
                        apiResponse = CreateSuccessApiResponse(new { Message = "Password changed successfully." });
                        break;
                    case 1:
                        apiResponse = CreateFailedApiResponse("", HttpStatusCode.NotFound, "User not found.");
                        break;
                    case 2:
                        await WriteAuditAsync(tenantId, userId, "UPDATE", "tbl_Users", userId.ToString(), "Password change failed: wrong current password");
                        apiResponse = CreateFailedApiResponse("", HttpStatusCode.BadRequest, "Current password is incorrect.");
                        break;
                    case 3:
                        apiResponse = CreateFailedApiResponse("", HttpStatusCode.BadRequest, "New password must be 8-72 characters and include upper case, lower case, a number and a special character.");
                        break;
                    case 4:
                        apiResponse = CreateFailedApiResponse("", HttpStatusCode.BadRequest, "New password must be different from the current password.");
                        break;
                    default:
                        apiResponse = CreateFailedApiResponse("", HttpStatusCode.InternalServerError, "Unable to change password.");
                        break;
                }
                return new ObjectResult(apiResponse);
            }
            catch (Exception ex)
            {
                apiResponse = CreateFailedApiResponse("", HttpStatusCode.InternalServerError, "An error occurred while processing your request");
                _logger.LogError(ex, "ChangePassword: Error occurred while changing password");
                return new ObjectResult(apiResponse);
            }
        }
        #endregion

        #region Helpers
        // Audit failures must never break the request.
        private async Task WriteAuditAsync(int tenantId, int? userId, string actionType, string tableName, string recordId, string newValues)
        {
            try
            {
                await _userService.InsertAuditLogAsync(new AuditLog
                {
                    TenantId = tenantId,
                    UserId = userId,
                    ActionType = actionType,
                    TableName = tableName,
                    RecordId = recordId,
                    NewValues = newValues,
                    IPAddress = GetIpAddress(),
                    UserAgent = GetUserAgent()
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Audit: Failed to write audit log - {ActionType} {TableName}", actionType, tableName);
            }
        }
        #endregion

        #region UpdateProfile
        [HttpPost]
        [Route("profile-update")]
        [Authorize]
        public async Task<IActionResult> UpdateProfile(UserProfileUpdateRequest model)
        {
            var response = new ApiResponse();
            try
            {
                var userId = CurrentUserId ?? 0;
                var tenantId = CurrentTenantId ?? 0;

                if (userId <= 0 || tenantId <= 0)
                {
                    return new ObjectResult(
                        CreateFailedApiResponse(
                            "",
                            HttpStatusCode.Unauthorized,
                            "Invalid or missing user authentication."
                        )
                    );
                }
                var data = await _userService.UpdateProfileAsync(model, userId, tenantId);

                switch (data.ReturnValue)
                {
                    case 0:
                        response = CreateSuccessApiResponse(
                            data,
                            HttpStatusCode.OK,
                            "Profile updated successfully."
                        );
                        break;

                    case 1:
                        response = CreateFailedApiResponse(
                            "",
                            HttpStatusCode.NotFound,
                            "User not found."
                        );
                        break;

                    case 2:
                        response = CreateFailedApiResponse(
                            "",
                            HttpStatusCode.Forbidden,
                            "Your account or role is inactive."
                        );
                        break;

                    default:
                        response = CreateFailedApiResponse(
                            "",
                            HttpStatusCode.BadRequest,
                            "Failed to update profile."
                        );
                        break;
                }

            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "UpdateProfile: Error occurred while updating profile");
                response = CreateFailedApiResponse("", HttpStatusCode.InternalServerError, "An error occurred while processing your request");
            }
            return new ObjectResult(response);
        }
        #endregion

        #region UpdateProfilePicture
        [HttpPost("profile-picture-update")]
        [Authorize]
        [Consumes("multipart/form-data")]
        public async Task<IActionResult> UpdateProfilePicture([FromForm] ProfilePictureUploadRequest profilePictureUploadRequest)
        {
            ApiResponse apiResponse;
            try
            {
                var result = await _userService.UpdateProfilePictureAsync(
                    CurrentUserId ?? 0, CurrentTenantId ?? 0, GetIpAddress(), profilePictureUploadRequest.File);

                apiResponse = result.ReturnValue == 0
                    ? CreateSuccessApiResponse(new { key = result.Key, url = result.Url },
                                               HttpStatusCode.OK, "Profile picture updated successfully.")
                    : CreateFailedApiResponse("", HttpStatusCode.NotFound, "User not found.");
            }
            catch (InvalidOperationException ex)
            {
                apiResponse = CreateFailedApiResponse("", HttpStatusCode.BadRequest, ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "UpdateProfilePicture error");
                apiResponse = CreateFailedApiResponse("", HttpStatusCode.InternalServerError,
                                                      "An error occurred while processing your request");
            }
            return new ObjectResult(apiResponse);
        }
        #endregion
    }
}