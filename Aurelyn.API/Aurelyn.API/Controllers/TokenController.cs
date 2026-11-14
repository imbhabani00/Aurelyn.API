using Asp.Versioning;
using Aurelyn.API.Helper;
using Aurelyn.Application.Dtos.Response;
using Aurelyn.Application.Dtos.Response.User;
using Aurelyn.Application.Services;
using Aurelyn.Domain.Constants;
using Aurelyn.Domain.Models.AuditLog;
using Aurelyn.Domain.Models.Authuntication;
using Aurelyn.Domain.Otp;
using Aurelyn.Domain.Session;
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
                
                var clientApp = string.IsNullOrWhiteSpace(model.ClientApp) ? "Web" : model.ClientApp.Trim();
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

                var otpModel = new OtpCode
                {
                    TenantId = user.TenantId,
                    UserId = user.UserId,
                    Purpose = OtpPurposeConstant.Login,
                    ClientApp = clientApp,
                    CodeHash = _tokenService.HashOtp(user.UserId, OtpPurposeConstant.Login, code),
                    ExpiresAt = DateTime.UtcNow.AddMinutes(_otpSettings.ExpiryMinutes),
                    IPAddress = GetIpAddress()
                };

                var otpResult = await _userService.CreateOtpAsync(otpModel);
                if (otpResult.ReturnValue != 0 || otpResult.OtpId <= 0)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.InternalServerError, "Unable to generate OTP.");
                    return new ObjectResult(apiResponse);
                }

                await _otpService.SendOtpAsync(user.Email, code, OtpPurposeConstant.Login, _otpSettings.ExpiryMinutes);
                await WriteAuditAsync(user.TenantId, user.UserId, "LOGIN", "tbl_OtpCodes", otpResult.OtpId.ToString(), "Password verified, OTP sent");

                _logger.LogInformation("AccessToken: OTP sent - UserId: {UserId}", user.UserId);

                apiResponse = CreateSuccessResponse(new
                {
                    OtpId = otpResult.OtpId,
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

                var sessionResponse = await _userService.CreateSessionAsync(new UserSession
                {
                    UserId = user.UserId,
                    RefreshTokenHash = refreshTokenHash,
                    ExpiresAt = refreshTokenExpiry,
                    DeviceInfo = GetUserAgent(),
                    IPAddress = GetIpAddress()
                });

                if (sessionResponse == null || sessionResponse.SessionId <= 0)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.InternalServerError, "Unable to create session.");
                    return new ObjectResult(apiResponse);
                }

                var accessToken = _tokenService.GenerateAccessToken(BuildClaims(user, otp.ClientApp, sessionResponse.SessionId));

                await WriteAuditAsync(user.TenantId, user.UserId, "LOGIN", "tbl_UserSessions", sessionResponse.SessionId.ToString(), "Login successful");

                _logger.LogInformation("VerifyOtp: User authenticated successfully - UserId: {UserId}", user.UserId);

                apiResponse = CreateSuccessResponse(new
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    ExpiresInSeconds = _jwtSettings.AccessTokenExpiryMinutes * 60,
                    UserId = user.UserId,
                    TenantId = user.TenantId,
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
                var clientApp = string.IsNullOrWhiteSpace(model.ClientApp) ? "Web" : model.ClientApp.Trim();
                var user = await _userService.GetByIdAsync(otp.UserId, otp.TenantId);
                if (user == null)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "User is inactive or not found.");
                    return new ObjectResult(apiResponse);
                }

                var code = _tokenService.GenerateOtp();
                var otpModel = new OtpCode
                {
                    TenantId = user.TenantId,
                    UserId = user.UserId,
                    Purpose = OtpPurposeConstant.ResendOtp,
                    ClientApp = clientApp,
                    CodeHash = _tokenService.HashOtp(user.UserId, OtpPurposeConstant.ResendOtp, code),
                    ExpiresAt = DateTime.UtcNow.AddMinutes(_otpSettings.ExpiryMinutes),
                    IPAddress = GetIpAddress()
                };

                var newOtpResult = await _userService.CreateOtpAsync(otpModel);
                if (newOtpResult.OtpId <= 0)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.InternalServerError, "Unable to generate OTP.");
                    return new ObjectResult(apiResponse);
                }

                await _otpService.SendOtpAsync(user.Email, code, otp.Purpose, _otpSettings.ExpiryMinutes);

                _logger.LogInformation("ResendOtp: OTP resent - UserId: {UserId}", user.UserId);

                apiResponse = CreateSuccessResponse(new
                {
                    OtpId = newOtpResult.OtpId,
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
                var userId = principal.GetUserId() ?? 0;
                var tenantId = principal.GetTenantId() ?? 0;
                var clientApp = principal.GetClientApp();

                if (userId <= 0 || tenantId <= 0)
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

                var newSession = new RotateSession
                {
                    SessionId = session.SessionId,
                    NewRefreshTokenHash = newRefreshTokenHash,
                    NewExpiresAt = refreshTokenExpiry,
                    DeviceInfo = GetUserAgent(),
                    IpAddress = GetIpAddress()
                };

                var rotateSessionResponse = await _userService.RotateSessionAsync(newSession);
                if (rotateSessionResponse.SessionId <= 0)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized, "Session is no longer valid. Please sign in again.");
                    return new ObjectResult(apiResponse);
                }

                // claims are rebuilt from the database so role changes apply on refresh
                var newAccessToken = _tokenService.GenerateAccessToken(BuildClaims(user, clientApp, rotateSessionResponse.SessionId));

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

                var userId = CurrentUserId ?? 0;
                var tenantId = CurrentTenantId ?? 0;
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

        #region Register
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] Register model)
        {
            var apiResponse = new ApiResponse();
            try
            {
                var clientApp = string.IsNullOrWhiteSpace(model.ClientApp) ? "Web" : model.ClientApp.Trim();

                var result = await _userService.RegisterAsync(model);

                switch (result.ReturnValue)
                {
                    case 0:
                        apiResponse = CreateSuccessResponse("", HttpStatusCode.OK, "Hey, you have registered successfully.");
                        break;

                    case 1:
                        apiResponse = CreateFailedApiResponse(
                            "", HttpStatusCode.BadRequest, "Organization not found.");
                        return new ObjectResult(apiResponse);

                    case 2:
                        apiResponse = CreateFailedApiResponse(
                            "", HttpStatusCode.Conflict, "An account with this email already exists.");
                        return new ObjectResult(apiResponse);

                    case 3:
                        apiResponse = CreateFailedApiResponse(
                            "", HttpStatusCode.BadRequest, "Registration role not found.");
                        return new ObjectResult(apiResponse);

                    case 4:
                        apiResponse = CreateSuccessResponse("", HttpStatusCode.OK, "Verification is pending. We are sending a new code.");
                        break;

                    default:
                        apiResponse = CreateFailedApiResponse(
                            "", HttpStatusCode.BadRequest, "Registration is not available right now.");
                        return new ObjectResult(apiResponse);
                }

                if (result.ReturnValue == 4)
                {
                    var latest = await _userService.GetLatestOtpAsync(result.UserId, OtpPurposeConstant.Register);
                    if (latest != null && latest.CreatedDate.AddSeconds(_otpSettings.ResendCooldownSeconds) > DateTime.UtcNow)
                        return new ObjectResult(CreateFailedApiResponse("", HttpStatusCode.TooManyRequests,
                            "Please wait before requesting a new code."));

                    var sentCount = await _userService.CountOtpSinceAsync(
                        result.UserId, OtpPurposeConstant.Register, DateTime.UtcNow.AddHours(-1));
                    if (sentCount >= _otpSettings.MaxResendsPerHour)
                        return new ObjectResult(CreateFailedApiResponse("", HttpStatusCode.TooManyRequests,
                            "OTP limit reached. Please try again later."));
                }

                var code = _tokenService.GenerateOtp();
                var otpModel = new OtpCode
                {
                    TenantId = result.TenantId,
                    UserId = result.UserId,
                    Purpose = OtpPurposeConstant.Register,
                    ClientApp = clientApp,
                    CodeHash = _tokenService.HashOtp(result.UserId, OtpPurposeConstant.Register, code),
                    ExpiresAt = DateTime.UtcNow.AddMinutes(_otpSettings.ExpiryMinutes),
                    IPAddress = GetIpAddress()
                };
                var otpResult = await _userService.CreateOtpAsync(otpModel);
                if (otpResult.ReturnValue != 0 || otpResult.OtpId <= 0)
                {
                    apiResponse = CreateFailedApiResponse("", HttpStatusCode.InternalServerError, "Unable to generate OTP.");
                    return new ObjectResult(apiResponse);
                }

                await _otpService.SendOtpAsync(model.Email.Trim(), code, OtpPurposeConstant.Register, _otpSettings.ExpiryMinutes);
                await WriteAuditAsync(result.TenantId, result.UserId, "CREATE", "tbl_Users", result.UserId.ToString(), "Self registration, verification code sent");

                _logger.LogInformation("Register: Account created - UserId: {UserId}", result.UserId);

                apiResponse = CreateSuccessResponse(new
                {
                    OtpId = otpResult.OtpId,
                    Email = MaskEmail(model.Email),
                    ExpiresInSeconds = _otpSettings.ExpiryMinutes * 60
                });
                return new ObjectResult(apiResponse);
            }
            catch (Exception ex)
            {
                apiResponse = CreateFailedApiResponse("", HttpStatusCode.InternalServerError, "An error occurred while processing your request");
                _logger.LogError(ex, "Register: Error occurred during registration");
                return new ObjectResult(apiResponse);
            }
        }
        #endregion

        #region Forgot Password
        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPassword model)
        {
            ApiResponse apiResponse;
            try
            {
                var clientApp = string.IsNullOrWhiteSpace(model.ClientApp) ? "Web" : model.ClientApp.Trim();
                var user = await _userService.GetByEmailAsync(model.Email.Trim(), model.TenantCode);

                var returnValue = (user == null || user.UserId <= 0 && user.ReturnValue == 0) ? 1 : user.ReturnValue;

                switch (returnValue)
                {
                    case 0:
                        var error = await SendPasswordResetOtpAsync(user!, clientApp);
                        if (error != null)
                        {
                            apiResponse = CreateFailedApiResponse("", HttpStatusCode.TooManyRequests, error);
                            break;
                        }
                        apiResponse = CreateSuccessResponse(new { }, HttpStatusCode.OK,
                            "A verification code has been sent to your email.");
                        break;

                    case 1:
                        apiResponse = CreateFailedApiResponse("", HttpStatusCode.NotFound,
                            "No account found with this email.");
                        break;

                    case 2:
                        apiResponse = CreateFailedApiResponse("", HttpStatusCode.Unauthorized,
                            "Your account is inactive. Please contact support.");
                        break;

                    case 4:
                        apiResponse = CreateFailedApiResponse("", HttpStatusCode.BadRequest,
                            "Your account is not verified yet. Please complete email verification first.");
                        break;

                    default:
                        _logger.LogWarning("ForgotPassword: Unexpected return value {Value}", returnValue);
                        apiResponse = CreateFailedApiResponse("", HttpStatusCode.BadRequest,
                            "Unable to send the code right now.");
                        break;
                }

                return new ObjectResult(apiResponse);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ForgotPassword: Error occurred");
                apiResponse = CreateFailedApiResponse("", HttpStatusCode.InternalServerError,
                    "An error occurred while processing your request");
                return new ObjectResult(apiResponse);
            }
        }

        // returns null when the code was sent, otherwise the message to show
        private async Task<string?> SendPasswordResetOtpAsync(UserLookupResponse user, string clientApp)
        {
            var latest = await _userService.GetLatestOtpAsync(user.UserId, OtpPurposeConstant.PasswordReset);
            if (latest != null)
            {
                var wait = (int)Math.Ceiling((latest.CreatedDate.AddSeconds(_otpSettings.ResendCooldownSeconds) - DateTime.UtcNow).TotalSeconds);
                if (wait > 0)
                    return $"Please wait {wait} second(s) before requesting a new code.";
            }

            var sentCount = await _userService.CountOtpSinceAsync(
                user.UserId, OtpPurposeConstant.PasswordReset, DateTime.UtcNow.AddHours(-1));
            if (sentCount >= _otpSettings.MaxResendsPerHour)
                return "Code limit reached. Please try again later.";

            var code = _tokenService.GenerateOtp();
            var otpModel = new OtpCode
            {
                TenantId = user.TenantId,
                UserId = user.UserId,
                Purpose = OtpPurposeConstant.PasswordReset,
                ClientApp = clientApp,
                CodeHash = _tokenService.HashOtp(user.UserId, OtpPurposeConstant.PasswordReset, code),
                ExpiresAt = DateTime.UtcNow.AddMinutes(_otpSettings.ExpiryMinutes),
                IPAddress = GetIpAddress()
            };

            var otpResult = await _userService.CreateOtpAsync(otpModel);
            if (otpResult.ReturnValue != 0 || otpResult.OtpId <= 0)
                return "Unable to generate the code. Please try again.";

            await _otpService.SendOtpAsync(user.Email, code, OtpPurposeConstant.PasswordReset, _otpSettings.ExpiryMinutes);
            await WriteAuditAsync(user.TenantId, user.UserId, "OTHER", "tbl_OtpCodes", otpResult.OtpId.ToString(), "Password reset code sent");
            return null;
        }
        #endregion

        #region Reset Password
        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPassword model)
        {
            ApiResponse apiResponse;
            try
            {
                if (model == null || string.IsNullOrWhiteSpace(model.Email) ||
                    string.IsNullOrWhiteSpace(model.Code) || string.IsNullOrWhiteSpace(model.NewPassword))
                {
                    return new ObjectResult(CreateFailedApiResponse("", HttpStatusCode.BadRequest,
                        "Email, code and new password are required."));
                }

                if (model.NewPassword != model.ConfirmPassword)
                {
                    return new ObjectResult(CreateFailedApiResponse("", HttpStatusCode.BadRequest,
                        "Password and confirm password do not match."));
                }

                // ---------- 1. user lookup (Users_GetByEmail return value) ----------
                var user = await _userService.GetByEmailAsync(model.Email.Trim(), model.TenantCode);

                // SP exits without a row for 1, 2 and 4, so user can be null or empty
                var lookupValue = (user == null || (user.UserId <= 0 && user.ReturnValue == 0)) ? 1 : user.ReturnValue;

                switch (lookupValue)
                {
                    case 0:
                        break;

                    case 1:
                        return new ObjectResult(CreateFailedApiResponse("", HttpStatusCode.NotFound,
                            "No account found with this email."));

                    case 2:
                        return new ObjectResult(CreateFailedApiResponse("", HttpStatusCode.Unauthorized,
                            "Your account is inactive. Please contact support."));

                    case 4:
                        return new ObjectResult(CreateFailedApiResponse("", HttpStatusCode.BadRequest,
                            "Your account is not verified yet. Please complete email verification first."));

                    default:
                        _logger.LogWarning("ResetPassword: Unexpected lookup value {Value}", lookupValue);
                        return new ObjectResult(CreateFailedApiResponse("", HttpStatusCode.BadRequest,
                            "Unable to reset the password right now."));
                }

                // ---------- 2. OTP state ----------
                // 0 = valid code, 1 = no OTP, 2 = used, 3 = expired, 4 = too many attempts, 5 = wrong code
                var otp = await _userService.GetLatestOtpAsync(user!.UserId, OtpPurposeConstant.PasswordReset);

                var otpState =
                    otp == null ? 1 :
                    otp.UsedAt != null ? 2 :
                    otp.ExpiresAt <= DateTime.UtcNow ? 3 :
                    otp.Attempts >= _otpSettings.MaxAttempts ? 4 :
                    !_tokenService.VerifyOtp(user.UserId, OtpPurposeConstant.PasswordReset, model.Code.Trim(), otp.CodeHash) ? 5 :
                    0;

                switch (otpState)
                {
                    case 0:
                        break;

                    case 1:
                        return new ObjectResult(CreateFailedApiResponse("", HttpStatusCode.NotFound,
                            "No code was requested for this email. Please request a new one."));

                    case 2:
                        return new ObjectResult(CreateFailedApiResponse("", HttpStatusCode.BadRequest,
                            "This code has already been used. Please request a new one."));

                    case 3:
                        return new ObjectResult(CreateFailedApiResponse("", HttpStatusCode.BadRequest,
                            "This code has expired. Please request a new one."));

                    case 4:
                        return new ObjectResult(CreateFailedApiResponse("", HttpStatusCode.TooManyRequests,
                            "Too many invalid attempts. Please request a new code."));

                    case 5:
                        var attempts = await _userService.IncrementOtpAttemptsAsync(otp!.OtpId);
                        var remaining = Math.Max(_otpSettings.MaxAttempts - attempts, 0);

                        await WriteAuditAsync(user.TenantId, user.UserId, "OTHER", "tbl_OtpCodes",
                            otp.OtpId.ToString(), "Password reset failed: invalid code");

                        _logger.LogWarning("ResetPassword: Invalid code - UserId: {UserId}", user.UserId);

                        return new ObjectResult(CreateFailedApiResponse("", HttpStatusCode.BadRequest,
                            remaining > 0
                                ? $"Invalid code. {remaining} attempt(s) remaining."
                                : "Too many invalid attempts. Please request a new code."));

                    default:
                        return new ObjectResult(CreateFailedApiResponse("", HttpStatusCode.BadRequest,
                            "Invalid or expired code."));
                }

                // ---------- 3. password strength BEFORE burning the code ----------
                if (!_userService.IsPasswordStrong(model.NewPassword))
                {
                    return new ObjectResult(CreateFailedApiResponse("", HttpStatusCode.BadRequest,
                        "Password must be 8-72 characters with upper, lower, number and special character."));
                }

                if (await _userService.IsSameAsCurrentPasswordAsync(user.UserId, user.TenantId, model.NewPassword))
                {
                    return new ObjectResult(CreateFailedApiResponse("", HttpStatusCode.BadRequest,
                        "New password must be different from your current password."));
                }

                // ---------- 4. one-time use ----------
                if (!await _userService.MarkOtpUsedAsync(otp!.OtpId))
                {
                    return new ObjectResult(CreateFailedApiResponse("", HttpStatusCode.BadRequest,
                        "This code is no longer valid. Please request a new one."));
                }

                // ---------- 5. update the password ----------
                var resetResult = await _userService.ResetPasswordAsync(new ResetPassword
                {
                    UserId = user.UserId,
                    TenantId = user.TenantId,
                    NewPassword = model.NewPassword
                });

                switch (resetResult.ReturnValue)
                {
                    case 0:
                        await WriteAuditAsync(user.TenantId, user.UserId, "UPDATE", "tbl_Users",
                            user.UserId.ToString(), "Password reset via OTP, all sessions revoked");

                        _logger.LogInformation("ResetPassword: Password reset - UserId: {UserId}", user.UserId);

                        apiResponse = CreateSuccessResponse(new { Message = "Password reset successfully." },
                            HttpStatusCode.OK, "Password reset successfully.");
                        break;

                    case 3:
                        apiResponse = CreateFailedApiResponse("", HttpStatusCode.BadRequest,
                            "Password must be 8-72 characters with upper, lower, number and special character.");
                        break;

                    case 4:
                        apiResponse = CreateFailedApiResponse("", HttpStatusCode.BadRequest,
                            "New password must be different from your current password.");
                        break;

                    default:
                        _logger.LogError("ResetPassword: Update failed - UserId: {UserId}, Value: {Value}",
                            user.UserId, resetResult.ReturnValue);
                        apiResponse = CreateFailedApiResponse("", HttpStatusCode.InternalServerError,
                            "Unable to reset the password.");
                        break;
                }

                return new ObjectResult(apiResponse);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ResetPassword: Error occurred");
                apiResponse = CreateFailedApiResponse("", HttpStatusCode.InternalServerError,
                    "An error occurred while processing your request");
                return new ObjectResult(apiResponse);
            }
        }
        #endregion
    }
}