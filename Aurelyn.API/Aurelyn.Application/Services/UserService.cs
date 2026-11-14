using Aurelyn.Application.Dtos.Response;
using Aurelyn.Application.Dtos.Response.Login;
using Aurelyn.Application.Dtos.Response.OtpResponse;
using Aurelyn.Application.Dtos.Response.Register;
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
using Microsoft.Extensions.Configuration;


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
        #endregion

        #region Constructor
        public UserService(IMapper mapper,
            IUserRepository userRepository,
            IConfiguration config)
        {
            _mapper = mapper;
            _userRepository = userRepository;
            _config = config;
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

        public async Task<bool> IsSameAsCurrentPasswordAsync(int userId, int tenantId, string password)
        {
            var hash = await _userRepository.GetPasswordHash(userId, tenantId);
            return !string.IsNullOrEmpty(hash) && VerifyPassword(password, hash);
        }
    }
}
