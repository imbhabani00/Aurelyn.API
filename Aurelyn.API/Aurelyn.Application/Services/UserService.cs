using Aurelyn.Application.Dtos.Response;
using Aurelyn.Application.Dtos.Response.Login;
using Aurelyn.Application.Dtos.Response.OtpResponse;
using Aurelyn.Application.Dtos.Response.Session;
using Aurelyn.Application.Dtos.Response.User;
using Aurelyn.Application.Repositories;
using Aurelyn.Domain.Models;
using Aurelyn.Domain.Models.AuditLog;
using Aurelyn.Domain.Models.Authuntication;
using Aurelyn.Domain.Models.User;
using Aurelyn.Domain.Otp;
using Aurelyn.Domain.Session;
using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Aurelyn.Application.Services
{
    #region Interface
    public interface IUserService
    {
        Task<AuthenticateResultResponse> AuthenticateAsync(string email, string tenantCode);
        Task<LoginFailureResponse> UpdateLoginFailureAsync(int userId);
        Task<bool> UpdateLoginSuccessAsync(int userId, bool markEmailVerified);
        Task<UserResponse> GetByIdAsync(int userId, int tenantId);
        bool VerifyPassword(string password, string passwordHash);
        string HashPassword(string password);
        bool IsPasswordStrong(string password);
        Task<GenericSaveResponse> ChangePasswordAsync(ResetPassword resetPassword);
        Task<OtpResponse> CreateOtpAsync(OtpCode otpCode);
        Task<OtpResponse> GetOtpByIdAsync(long otpId);
        Task<OtpResponse> GetLatestOtpAsync(int userId, string purpose);
        Task<int> CountOtpSinceAsync(int userId, string purpose, DateTime since);
        Task<int> IncrementOtpAttemptsAsync(long otpId);
        Task<bool> MarkOtpUsedAsync(long otpId);
        Task<UserSessionResponse> CreateSessionAsync(UserSession userSession);
        Task<UserSessionResponse> GetSessionByHashAsync(string refreshTokenHash);
        Task<RotateSessionResponse> RotateSessionAsync(RotateSession rotateSession);
        Task<bool> RevokeSessionAsync(int userId, string refreshTokenHash);
        Task<int> RevokeAllSessionsAsync(int userId, long? exceptSessionId);
        Task InsertAuditLogAsync(AuditLog auditLog);
        Task<GenericSaveResponse> RegisterAsync(Register model);
        Task<UserLookupResponse> GetByEmailAsync(string email, string? tenantCode);
        Task<GenericSaveResponse> ResetPasswordAsync(ResetPassword resetPassword);
        Task<bool> IsSameAsCurrentPasswordAsync(int userId, int tenantId, string password);
        Task<GenericSaveResponse> UpdateProfileAsync(UserProfileUpdateRequest model, int userId, int tenantId);
        Task<ProfilePictureResponse> UpdateProfilePictureAsync(int userId, int tenantId, string ipAddress, IFormFile? file);
    }
    #endregion

    public class UserService : IUserService
    {
        #region Properties
        private readonly IMapper _mapper;
        private readonly IUserRepository _userRepository;
        private readonly IConfiguration _config;
        private const int DefaultBcryptWorkFactor = 12;
        private const int MinPasswordLength = 8;
        private const int MaxPasswordLength = 72;
        private readonly ILogger<UserService> _logger;
        private readonly IR2StorageService _r2StorageService;
        #endregion

        #region Constructor
        public UserService(IMapper mapper,
            IUserRepository userRepository,
            IConfiguration config,
            ILogger<UserService> logger,
            IR2StorageService r2StorageService)
        {
            _mapper = mapper;
            _userRepository = userRepository;
            _config = config;
            _logger = logger;
            _r2StorageService = r2StorageService;
        }
        #endregion

        #region AuthenticateAsync
        public async Task<AuthenticateResultResponse> AuthenticateAsync(string email, string tenantCode)
        {
            var request = await _userRepository.Authenticate(email, tenantCode);
            var response = _mapper.Map<AuthenticateResult, AuthenticateResultResponse>(request);
            return response;
        }
        #endregion

        #region UpdateLoginFailureAsync
        public async Task<LoginFailureResponse> UpdateLoginFailureAsync(int userId)
        {
            var result = await _userRepository.UpdateLoginFailure(userId);
            var response = _mapper.Map<LoginFailureResult, LoginFailureResponse>(result);
            return response;
        }
        #endregion

        #region UpdateLoginSuccessAsync
        public async Task<bool> UpdateLoginSuccessAsync(int userId, bool markEmailVerified)
        {
            return await _userRepository.UpdateLoginSuccess(userId, markEmailVerified);
        }
        #endregion

        #region GetByIdAsync
        public async Task<UserResponse> GetByIdAsync(int userId, int tenantId)
        {
            var user = await _userRepository.GetById(userId, tenantId);
            if (user == null)
            {
                return null;
            }

            var response = _mapper.Map<User, UserResponse>(user);
            response.ProfilePictureUrl = _r2StorageService.GetPublicUrl(response.ProfilePictureKey);
            return response;
        }
        #endregion

        #region VerifyPassword
        public bool VerifyPassword(string password, string passwordHash)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(passwordHash))
            {
                return false;
            }

            try
            {
                return BCrypt.Net.BCrypt.Verify(password, passwordHash);
            }
            catch (Exception)
            {
                return false;
            }
        }
        #endregion

        #region HashPassword
        public string HashPassword(string password)
        {
            var workFactor = int.TryParse(_config["Security:BcryptWorkFactor"], out var configured)
                ? configured
                : DefaultBcryptWorkFactor;

            return BCrypt.Net.BCrypt.HashPassword(password, workFactor);
        }
        #endregion

        #region IsPasswordStrong
        public bool IsPasswordStrong(string password)
        {
            if (string.IsNullOrEmpty(password)
                || password.Length < MinPasswordLength
                || password.Length > MaxPasswordLength)
            {
                return false;
            }

            return password.Any(char.IsUpper)
                && password.Any(char.IsLower)
                && password.Any(char.IsDigit)
                && password.Any(c => !char.IsLetterOrDigit(c));
        }
        #endregion

        #region ChangePasswordAsync
        public async Task<GenericSaveResponse> ChangePasswordAsync(ResetPassword resetPassword)
        {
            var currentHash = await _userRepository.GetPasswordHash(resetPassword.UserId, resetPassword.TenantId);
            if (string.IsNullOrEmpty(currentHash)) return new GenericSaveResponse { ReturnValue = 1 };
            if (!VerifyPassword(resetPassword.CurrentPassword, currentHash)) return new GenericSaveResponse { ReturnValue = 2 };
            if (!IsPasswordStrong(resetPassword.NewPassword)) return new GenericSaveResponse { ReturnValue = 3 };
            if (VerifyPassword(resetPassword.NewPassword, currentHash)) return new GenericSaveResponse { ReturnValue = 4 };

            resetPassword.NewPasswordHash = HashPassword(resetPassword.NewPassword);
            var changed = await _userRepository.ChangePassword(resetPassword);
            if (changed.ReturnValue != 0) return new GenericSaveResponse { ReturnValue = 1 };

            await _userRepository.RevokeAllSessions(resetPassword.UserId, resetPassword.CurrentSessionId);
            return new GenericSaveResponse { ReturnValue = 0 };
        }
        #endregion

        #region CreateOtpAsync
        public async Task<OtpResponse> CreateOtpAsync(OtpCode otpCode)
        {
            var request = await _userRepository.CreateOtp(otpCode);
            var response = _mapper.Map<OtpCode, OtpResponse>(request);
            return response;
        }
        #endregion

        #region GetOtpByIdAsync
        public async Task<OtpResponse> GetOtpByIdAsync(long otpId)
        {
            var otp = await _userRepository.GetOtpById(otpId);
            if (otp == null)
            {
                return null;
            }

            var response = _mapper.Map<OtpCode, OtpResponse>(otp);
            return response;
        }
        #endregion

        #region GetLatestOtpAsync
        public async Task<OtpResponse> GetLatestOtpAsync(int userId, string purpose)
        {
            var otp = await _userRepository.GetLatestOtp(userId, purpose);
            if (otp == null)
            {
                return null;
            }

            var response = _mapper.Map<OtpCode, OtpResponse>(otp);
            return response;
        }
        #endregion

        #region CountOtpSinceAsync
        public async Task<int> CountOtpSinceAsync(int userId, string purpose, DateTime since)
        {
            return await _userRepository.CountOtpSince(userId, purpose, since);
        }
        #endregion

        #region IncrementOtpAttemptsAsync
        public async Task<int> IncrementOtpAttemptsAsync(long otpId)
        {
            return await _userRepository.IncrementOtpAttempts(otpId);
        }
        #endregion

        #region MarkOtpUsedAsync
        public async Task<bool> MarkOtpUsedAsync(long otpId)
        {
            return await _userRepository.MarkOtpUsed(otpId);
        }
        #endregion

        #region CreateSessionAsync
        public async Task<UserSessionResponse> CreateSessionAsync(UserSession userSession)
        {
            var request = await _userRepository.CreateSession(userSession);
            var resposne = _mapper.Map<UserSession, UserSessionResponse>(request);
            return resposne;
        }
        #endregion

        #region GetSessionByHashAsync
        public async Task<UserSessionResponse> GetSessionByHashAsync(string refreshTokenHash)
        {
            var session = await _userRepository.GetSessionByHash(refreshTokenHash);
            var response = _mapper.Map<UserSession, UserSessionResponse>(session);
            return response;
        }
        #endregion

        #region RotateSessionAsync
        public async Task<RotateSessionResponse> RotateSessionAsync(RotateSession rotateSession)
        {
            var request = await _userRepository.RotateSession(rotateSession);
            var response = _mapper.Map<RotateSession, RotateSessionResponse>(request);
            return response;
        }
        #endregion

        #region RevokeSessionAsync
        public async Task<bool> RevokeSessionAsync(int userId, string refreshTokenHash)
        {
            return await _userRepository.RevokeSession(userId, refreshTokenHash);
        }
        #endregion

        #region RevokeAllSessionsAsync
        public async Task<int> RevokeAllSessionsAsync(int userId, long? exceptSessionId)
        {
            return await _userRepository.RevokeAllSessions(userId, exceptSessionId);
        }
        #endregion

        #region InsertAuditLogAsync
        public async Task InsertAuditLogAsync(AuditLog auditLog)
        {
            await _userRepository.InsertAuditLog(auditLog);
        }
        #endregion

        #region RegisterAsync
        public async Task<GenericSaveResponse> RegisterAsync(Register model)
        {
            var passwordHash = HashPassword(model.Password);
            model.FirstName.Trim();
            model.LastName?.Trim();
            model.Email.Trim();
            model.PasswordHash = passwordHash;
            model.TenantCode = string.IsNullOrWhiteSpace(model.TenantCode) ? null : model.TenantCode.Trim();
            model.RoleCode = "PATIENT";
            var result = await _userRepository.Register(model);
            var response = _mapper.Map<SaveResponse, GenericSaveResponse>(result);
            return response;
        }
        #endregion

        #region GetByEmailAsync
        public async Task<UserLookupResponse> GetByEmailAsync(string email, string? tenantCode)
        {
            var result = await _userRepository.GetByEmail(email, tenantCode);
            var response = _mapper.Map<UserLookup, UserLookupResponse>(result);
            return response;
        }
        #endregion

        #region ResetPasswordAsync
        public async Task<GenericSaveResponse> ResetPasswordAsync(ResetPassword resetPassword)
        {
            if (!IsPasswordStrong(resetPassword.NewPassword))
                return new GenericSaveResponse { ReturnValue = 3 };

            if (await IsSameAsCurrentPasswordAsync(resetPassword.UserId, resetPassword.TenantId, resetPassword.NewPassword))
                return new GenericSaveResponse { ReturnValue = 4 };

            resetPassword.NewPasswordHash = HashPassword(resetPassword.NewPassword);
            var changed = await _userRepository.ChangePassword(resetPassword);
            if (changed.ReturnValue != 0)
                return new GenericSaveResponse { ReturnValue = 1 };

            await _userRepository.RevokeAllSessions(resetPassword.UserId, null);
            return new GenericSaveResponse { ReturnValue = 0 };
        }
        #endregion

        #region IsSameAsCurrentPasswordAsync
        public async Task<bool> IsSameAsCurrentPasswordAsync(int userId, int tenantId, string password)
        {
            var hash = await _userRepository.GetPasswordHash(userId, tenantId);
            return !string.IsNullOrEmpty(hash) && VerifyPassword(password, hash);
        }
        #endregion

        #region UpdateProfileAsync
        public async Task<GenericSaveResponse> UpdateProfileAsync(UserProfileUpdateRequest model, int userId, int tenantId)
        {
            var request = await _userRepository.UpdateProfile(model, userId, tenantId);
            var response = _mapper.Map<SaveResponse, GenericSaveResponse>(request);
            return response;
        }
        #endregion

        #region UpdateProfilePictureAsync
        public async Task<ProfilePictureResponse> UpdateProfilePictureAsync(int userId, int tenantId, string ipAddress, IFormFile? file)
        {
            string? newKey = null;

            if (file is { Length: > 0 })
            {
                var ext = file.ContentType switch
                {
                    "image/jpeg" => ".jpg",
                    "image/png" => ".png",
                    "image/webp" => ".webp",
                    _ => throw new InvalidOperationException("Only JPG, PNG or WEBP images are allowed.")
                };
                if (file.Length > 5 * 1024 * 1024)
                    throw new InvalidOperationException("Image must be 5 MB or smaller.");

                newKey = $"images/profile/{tenantId}/{userId}/{Guid.NewGuid():N}{ext}";
                await using var stream = file.OpenReadStream();
                await _r2StorageService.UploadAsync(stream, newKey, file.ContentType);
            }

            ProfilePicDbResult db;
            try
            {
                db = await _userRepository.UpdateProfilePicture(userId, tenantId, ipAddress, newKey);
            }
            catch
            {
                if (newKey != null) await SafeDelete(newKey);
                throw;
            }

            if (db.ReturnValue != 0)
            {
                if (newKey != null) await SafeDelete(newKey);
                return new ProfilePictureResponse { ReturnValue = db.ReturnValue };
            }

            if (!string.IsNullOrEmpty(db.OldKey) && db.OldKey != newKey)
                await SafeDelete(db.OldKey);

            return new ProfilePictureResponse
            {
                ReturnValue = 0,
                Key = newKey,
                Url = _r2StorageService.GetPublicUrl(newKey)
            };
        }

        private async Task SafeDelete(string key)
        {
            try { await _r2StorageService.DeleteAsync(key); }
            catch (Exception ex) { _logger.LogWarning(ex, "R2 delete failed for {Key}", key); }
        }
        #endregion
    }
}