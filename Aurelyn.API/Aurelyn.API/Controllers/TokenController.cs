using Asp.Versioning;
using Aurelyn.Application.Dtos.Response;
using Aurelyn.Application.Dtos.Response.User;
using Aurelyn.Application.Services;
using Aurelyn.Domain.AuditLog;
using Aurelyn.Domain.Authuntication;
using Aurelyn.Domain.Constants;
using Aurelyn.Domain.Otp;
using Aurelyn.Domain.Settings;
using Aurelyn.Domain.Token;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Security.Claims;

namespace Aurelyn.API.Controllers
{
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v{version:apiVersion}/[controller]")]
    public class TokenController : BaseController
    {
        #region Properties
        private readonly ITokenService _tokenService;
        private readonly IUserService _userService;
        private readonly IOtpService _otpService;
        private readonly ILogger<TokenController> _logger;
        private readonly JwtSettings _jwtSettings;
        private readonly OtpSettings _otpSettings;
        #endregion

        #region Constructor
        public TokenController(
            ITokenService tokenService,
            IUserService userService,
            IOtpService otpService,
            ILogger<TokenController> logger,
            JwtSettings jwtSettings,
            OtpSettings otpSettings)
        {
            _tokenService = tokenService;
            _userService = userService;
            _otpService = otpService;
            _logger = logger;
            _jwtSettings = jwtSettings;
            _otpSettings = otpSettings;
        }
        #endregion

        #region AccessToken
        [HttpPost]
        [Route("access-token")]
        [AllowAnonymous]
        public async Task<IActionResult> AccessToken([FromBody] AuthModel model)
        {
            var apiResponse = new ApiResponse();
            try
            {
                if (model == null || string.IsNullOrWhiteSpace(model.Email) || string.IsNullOrWhiteSpace(model.Password))
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.BadRequest, "Email and password are required.");
                    return new ObjectResult(apiResponse);
                }
                var clientApp = string.IsNullOrWhiteSpace(model.ClientApp) ? "Web" : model.ClientApp.Trim();
                if (clientApp.Length > 30)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.BadRequest, "Invalid client app.");
                    return new ObjectResult(apiResponse);
                }

                var result = await _userService.AuthenticateAsync(model.Email.Trim(), model.TenantCode);

                if (result == null)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.NotFound, "Data not found.");
                    return new ObjectResult(apiResponse);
                }

                if (result.ReturnValue != 0)
                {
                    switch (result.ReturnValue)
                    {
                        case 1:
                            apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "Invalid credentials.");
                            break;
                        case 2:
                            apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "User is inactive.");
                            break;
                        case 3:
                            apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "Account is locked. Please try again later.");
                            break;
                        case 4:
                            apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "Account is not verified or invitation is not accepted.");
                            break;
                        default:
                            apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "Authentication failed.");
                            break;
                    }
                    return new ObjectResult(apiResponse);
                }

                var user = result.AuthunticateUser;
                if (user == null)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.NotFound, "Data not found.");
                    return new ObjectResult(apiResponse);
                }

                // password check
                if (!_userService.VerifyPassword(model.Password, user.PasswordHash))
                {
                    var failure = await _userService.UpdateLoginFailureAsync(user.UserId);
                    await WriteAuditAsync(user.TenantId, user.UserId, "LOGIN", "tbl_Users", user.UserId.ToString(), "Login failed: invalid password");

                    var isLocked = failure != null && failure.LockedUntil.HasValue && failure.LockedUntil.Value > DateTime.UtcNow;
                    var message = isLocked ? "Account is locked. Please try again later." : "Invalid credentials.";

                    _logger.LogWarning("AccessToken: Invalid password - UserId: {UserId}", user.UserId);
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, message);
                    return new ObjectResult(apiResponse);
                }

                // create and send the OTP
                var code = _tokenService.GenerateOtp();
                var codeHash = _tokenService.HashOtp(user.UserId, OtpPurposeConstant.Login, code);
                var expiresAt = DateTime.UtcNow.AddMinutes(_otpSettings.ExpiryMinutes);

                var otpId = await _userService.CreateOtpAsync(user.TenantId, user.UserId, OtpPurposeConstant.Login, clientApp, codeHash, expiresAt, GetIpAddress());
                if (otpId <= 0)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.InternalServerError, "Unable to generate OTP.");
                    return new ObjectResult(apiResponse);
                }

                await _otpService.SendOtpAsync(user.Email, code, OtpPurposeConstant.Login, _otpSettings.ExpiryMinutes);
                await WriteAuditAsync(user.TenantId, user.UserId, "LOGIN", "tbl_OtpCodes", otpId.ToString(), "Password verified, OTP sent");

                _logger.LogInformation("AccessToken: OTP sent - UserId: {UserId}", user.UserId);

                apiResponse = CreateSuccessResponse(new
                {
                    OtpId = otpId,
                    Email = MaskEmail(user.Email),
                    ExpiresInSeconds = _otpSettings.ExpiryMinutes * 60
                });
                return new ObjectResult(apiResponse);
            }
            catch (Exception ex)
            {
                apiResponse = CreateFailedApiResponse("", HttpStatusCode.InternalServerError, "An error occurred while processing your request");
                _logger.LogError(ex, "AccessToken: Error occurred during authentication");
                return new ObjectResult(apiResponse);
            }
        }
        #endregion

        #region Verify Otp
        // Step 2 of login: check the OTP and issue the tokens.
        [HttpPost("verify-otp")]
        [AllowAnonymous]
        public async Task<IActionResult> VerifyOtp([FromBody] VerifyOtpModel model)
        {
            var apiResponse = new ApiResponse();
            try
            {
                if (model == null || model.OtpId <= 0 || string.IsNullOrWhiteSpace(model.Code))
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.BadRequest, "OtpId and code are required.");
                    return new ObjectResult(apiResponse);
                }

                var otp = await _userService.GetOtpByIdAsync(model.OtpId);
                if (otp == null)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.NotFound, "OTP not found.");
                    return new ObjectResult(apiResponse);
                }

                if (otp.Purpose == OtpPurposeConstant.PasswordReset)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.BadRequest, "This OTP cannot be used to sign in.");
                    return new ObjectResult(apiResponse);
                }

                if (otp.UsedAt != null)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.BadRequest, "OTP has already been used.");
                    return new ObjectResult(apiResponse);
                }

                if (otp.ExpiresAt <= DateTime.UtcNow)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "OTP has expired. Please request a new one.");
                    return new ObjectResult(apiResponse);
                }

                if (otp.Attempts >= _otpSettings.MaxAttempts)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.TooManyRequests, "Too many invalid attempts. Please request a new OTP.");
                    return new ObjectResult(apiResponse);
                }

                if (!_tokenService.VerifyOtp(otp.UserId, otp.Purpose, model.Code.Trim(), otp.CodeHash))
                {
                    var attempts = await _userService.IncrementOtpAttemptsAsync(otp.OtpId);
                    var remaining = Math.Max(_otpSettings.MaxAttempts - attempts, 0);

                    await WriteAuditAsync(otp.TenantId, otp.UserId, "LOGIN", "tbl_OtpCodes", otp.OtpId.ToString(), "Login failed: invalid OTP");

                    _logger.LogWarning("VerifyOtp: Invalid OTP - UserId: {UserId}", otp.UserId);
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, $"Invalid OTP. {remaining} attempt(s) remaining.");
                    return new ObjectResult(apiResponse);
                }

                // one-time use, also protects against double submit
                if (!await _userService.MarkOtpUsedAsync(otp.OtpId))
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "OTP is no longer valid.");
                    return new ObjectResult(apiResponse);
                }

                var user = await _userService.GetByIdAsync(otp.UserId, otp.TenantId);
                if (user == null)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "User is inactive or not found.");
                    return new ObjectResult(apiResponse);
                }

                await _userService.UpdateLoginSuccessAsync(user.UserId, otp.Purpose == OtpPurposeConstant.Register);

                // tokens are issued for the same app that asked for the OTP
                var refreshToken = _tokenService.GenerateRefreshToken();
                var refreshTokenHash = _tokenService.HashToken(refreshToken);
                var refreshTokenExpiry = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryDays);

                var sessionId = await _userService.CreateSessionAsync(user.UserId, refreshTokenHash, refreshTokenExpiry, GetUserAgent(), GetIpAddress());
                if (sessionId <= 0)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.InternalServerError, "Unable to create session.");
                    return new ObjectResult(apiResponse);
                }

                var accessToken = _tokenService.GenerateAccessToken(BuildClaims(user, otp.ClientApp, sessionId));

                await WriteAuditAsync(user.TenantId, user.UserId, "LOGIN", "tbl_UserSessions", sessionId.ToString(), "Login successful");

                _logger.LogInformation("VerifyOtp: User authenticated successfully - UserId: {UserId}", user.UserId);

                apiResponse = CreateSuccessResponse(new
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    ExpiresInSeconds = _jwtSettings.AccessTokenExpiryMinutes * 60,
                    UserId = user.UserId,
                    RoleCode = user.RoleCode,
                    RoleName = user.RoleName,
                    RoleId = user.RoleId,
                });
                return new ObjectResult(apiResponse);
            }
            catch (Exception ex)
            {
                apiResponse = CreateFailedApiResponse("", HttpStatusCode.InternalServerError, "An error occurred while processing your request");
                _logger.LogError(ex, "VerifyOtp: Error occurred while verifying OTP");
                return new ObjectResult(apiResponse);
            }
        }
        #endregion

        #region Resend Otp
        [HttpPost("resend-otp")]
        [AllowAnonymous]
        public async Task<IActionResult> ResendOtp([FromBody] ResendOtpModel model)
        {
            var apiResponse = new ApiResponse();
            try
            {
                if (model == null || model.OtpId <= 0)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.BadRequest, "OtpId is required.");
                    return new ObjectResult(apiResponse);
                }

                var otp = await _userService.GetOtpByIdAsync(model.OtpId);
                if (otp == null)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.NotFound, "OTP not found.");
                    return new ObjectResult(apiResponse);
                }

                if (otp.UsedAt != null)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.BadRequest, "OTP has already been used.");
                    return new ObjectResult(apiResponse);
                }

                // cooldown between two OTPs
                var latest = await _userService.GetLatestOtpAsync(otp.UserId, otp.Purpose);
                if (latest != null)
                {
                    if (latest.UsedAt != null)
                    {
                        apiResponse = CreateFailedApiResponse("", HttpStatusCode.BadRequest, "OTP has already been used. Please sign in again.");
                        return new ObjectResult(apiResponse);
                    }

                    var waitSeconds = (int)Math.Ceiling((latest.CreatedDate.AddSeconds(_otpSettings.ResendCooldownSeconds) - DateTime.UtcNow).TotalSeconds);
                    if (waitSeconds > 0)
                    {
                        apiResponse = CreateFailedApiResponse("", HttpStatusCode.TooManyRequests, $"Please wait {waitSeconds} second(s) before requesting a new OTP.");
                        return new ObjectResult(apiResponse);
                    }
                }

                // hourly limit
                var sentCount = await _userService.CountOtpSinceAsync(otp.UserId, otp.Purpose, DateTime.UtcNow.AddHours(-1));
                if (sentCount >= _otpSettings.MaxResendsPerHour)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.TooManyRequests, "OTP limit reached. Please try again later.");
                    return new ObjectResult(apiResponse);
                }

                var user = await _userService.GetByIdAsync(otp.UserId, otp.TenantId);
                if (user == null)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "User is inactive or not found.");
                    return new ObjectResult(apiResponse);
                }

                var code = _tokenService.GenerateOtp();
                var codeHash = _tokenService.HashOtp(user.UserId, otp.Purpose, code);
                var expiresAt = DateTime.UtcNow.AddMinutes(_otpSettings.ExpiryMinutes);

                var newOtpId = await _userService.CreateOtpAsync(user.TenantId, user.UserId, otp.Purpose, otp.ClientApp, codeHash, expiresAt, GetIpAddress());
                if (newOtpId <= 0)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.InternalServerError, "Unable to generate OTP.");
                    return new ObjectResult(apiResponse);
                }

                await _otpService.SendOtpAsync(user.Email, code, otp.Purpose, _otpSettings.ExpiryMinutes);

                _logger.LogInformation("ResendOtp: OTP resent - UserId: {UserId}", user.UserId);

                apiResponse = CreateSuccessResponse(new
                {
                    OtpId = newOtpId,
                    Email = MaskEmail(user.Email),
                    ExpiresInSeconds = _otpSettings.ExpiryMinutes * 60
                });
                return new ObjectResult(apiResponse);
            }
            catch (Exception ex)
            {
                apiResponse = CreateFailedApiResponse("", HttpStatusCode.InternalServerError, "An error occurred while processing your request");
                _logger.LogError(ex, "ResendOtp: Error occurred while resending OTP");
                return new ObjectResult(apiResponse);
            }
        }
        #endregion

        #region Refresh Token
        [HttpPost("refresh-token")]
        [AllowAnonymous]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenModel model)
        {
            var apiResponse = new ApiResponse();
            try
            {
                if (model == null || string.IsNullOrWhiteSpace(model.AccessToken) || string.IsNullOrWhiteSpace(model.RefreshToken))
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.BadRequest, "Access token and refresh token are required.");
                    return new ObjectResult(apiResponse);
                }

                var principal = _tokenService.GetPrincipalFromExpiredToken(model.AccessToken);
                var userIdClaim = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var tenantIdClaim = principal.FindFirst("TenantId")?.Value;
                var clientApp = principal.FindFirst("ClientApp")?.Value ?? "Web";

                if (!int.TryParse(userIdClaim, out var userId) || !int.TryParse(tenantIdClaim, out var tenantId))
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "Invalid access token");
                    return new ObjectResult(apiResponse);
                }

                var refreshTokenHash = _tokenService.HashToken(model.RefreshToken);
                var session = await _userService.GetSessionByHashAsync(refreshTokenHash);

                switch (session.ReturnValue)
                {
                    case 0:
                        break;
                    case 2:
                        // an already-revoked token is being used again: treat it as stolen
                        await _userService.RevokeAllSessionsAsync(session.UserId, null);
                        await WriteAuditAsync(session.TenantId, session.UserId, "LOGOUT", "tbl_UserSessions", session.SessionId.ToString(), "Refresh token reuse detected, all sessions revoked");
                        _logger.LogWarning("RefreshToken: Token reuse detected - UserId: {UserId}", session.UserId);
                        apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "Session is no longer valid. Please sign in again.");
                        return new ObjectResult(apiResponse);
                    case 3:
                        apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "Refresh token has expired. Please sign in again.");
                        return new ObjectResult(apiResponse);
                    default:
                        apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "Invalid refresh token");
                        return new ObjectResult(apiResponse);
                }

                // the refresh token must belong to the user in the access token
                if (session.UserId != userId || session.TenantId != tenantId)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "Invalid refresh token");
                    return new ObjectResult(apiResponse);
                }

                var user = await _userService.GetByIdAsync(userId, tenantId);
                if (user == null)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "User is inactive or not found.");
                    return new ObjectResult(apiResponse);
                }

                var newRefreshToken = _tokenService.GenerateRefreshToken();
                var newRefreshTokenHash = _tokenService.HashToken(newRefreshToken);
                var refreshTokenExpiry = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryDays);

                var newSessionId = await _userService.RotateSessionAsync(session.SessionId, newRefreshTokenHash, refreshTokenExpiry, GetUserAgent(), GetIpAddress());
                if (newSessionId <= 0)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "Session is no longer valid. Please sign in again.");
                    return new ObjectResult(apiResponse);
                }

                // claims are rebuilt from the database so role changes apply on refresh
                var newAccessToken = _tokenService.GenerateAccessToken(BuildClaims(user, clientApp, newSessionId));

                apiResponse = CreateSuccessResponse(new
                {
                    AccessToken = newAccessToken,
                    RefreshToken = newRefreshToken,
                    ExpiresInSeconds = _jwtSettings.AccessTokenExpiryMinutes * 60
                });
                return new ObjectResult(apiResponse);
            }
            catch (SecurityTokenException ex)
            {
                _logger.LogError(ex, "Refresh: Token validation failed");
                apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "Token validation failed");
                return new ObjectResult(apiResponse);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Refresh: Error occurred during token refresh");
                apiResponse = CreateFailedApiResponse("", HttpStatusCode.InternalServerError, "An error occurred while processing your request");
                return new ObjectResult(apiResponse);
            }
        }
        #endregion

        #region Logout
        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout([FromBody] LogoutModel model)
        {
            var apiResponse = new ApiResponse();
            try
            {
                if (model == null || string.IsNullOrWhiteSpace(model.RefreshToken))
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.BadRequest, "Refresh token is required.");
                    return new ObjectResult(apiResponse);
                }

                var userId = GetClaimInt("UserId");
                var tenantId = GetClaimInt("TenantId");
                if (userId <= 0)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "Invalid access token");
                    return new ObjectResult(apiResponse);
                }

                var refreshTokenHash = _tokenService.HashToken(model.RefreshToken);
                var revoked = await _userService.RevokeSessionAsync(userId, refreshTokenHash);
                if (!revoked)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.NotFound, "Session not found or already logged out.");
                    return new ObjectResult(apiResponse);
                }

                await WriteAuditAsync(tenantId, userId, "LOGOUT", "tbl_UserSessions", GetClaimInt("SessionId").ToString(), "Logout successful");

                _logger.LogInformation("Logout: User logged out - UserId: {UserId}", userId);

                apiResponse = CreateSuccessResponse(new { Message = "Logged out successfully." });
                return new ObjectResult(apiResponse);
            }
            catch (Exception ex)
            {
                apiResponse = CreateFailedApiResponse("", HttpStatusCode.InternalServerError, "An error occurred while processing your request");
                _logger.LogError(ex, "Logout: Error occurred during logout");
                return new ObjectResult(apiResponse);
            }
        }
        #endregion

        #region Helpers
        private static List<Claim> BuildClaims(UserResponse user, string clientApp, long sessionId)
        {
            return new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()),
                new Claim("UserId", user.UserId.ToString()),
                new Claim("RoleId", user.RoleId.ToString()),
                new Claim("RoleName", user.RoleName ?? "User"),
                new Claim(ClaimTypes.Role, user.RoleCode ?? "User"),
                new Claim("RoleCode", user.RoleCode ?? "User"),
                new Claim(ClaimTypes.Email, user.Email ?? string.Empty),
                new Claim("TenantId", user.TenantId.ToString()),
                new Claim("ClientApp", clientApp ?? "Web"),
                new Claim("SessionId", sessionId.ToString()),
                new Claim("jti", Guid.NewGuid().ToString())
            };
        }

        private int GetClaimInt(string claimType)
        {
            var value = HttpContext.User.FindFirst(claimType)?.Value;
            return int.TryParse(value, out var result) ? result : 0;
        }

        private string GetIpAddress()
        {
            return HttpContext.Connection.RemoteIpAddress?.ToString();
        }

        private string GetUserAgent()
        {
            var userAgent = Request.Headers["User-Agent"].ToString();
            return userAgent.Length > 500 ? userAgent.Substring(0, 500) : userAgent;
        }

        private static string MaskEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email) || !email.Contains('@'))
            {
                return string.Empty;
            }

            var parts = email.Split('@');
            var name = parts[0];
            var masked = name.Length <= 2 ? name.Substring(0, 1) + "*" : name.Substring(0, 2) + new string('*', name.Length - 2);
            return $"{masked}@{parts[1]}";
        }

        // Audit failures must never break the login flow.
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
    }
}