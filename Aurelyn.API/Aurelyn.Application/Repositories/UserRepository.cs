using Aurelyn.Domain.AuditLog;
using Aurelyn.Domain.Authuntication;
using Aurelyn.Domain.Models;
using Aurelyn.Domain.Otp;
using Aurelyn.Domain.Session;
using Dapper;
using Microsoft.Extensions.Configuration;
using System.Data;

namespace Aurelyn.Application.Repositories
{
    #region Interface
    public interface IUserRepository
    {
        Task<AuthenticateResult> Authenticate(string email, string tenantCode);
        Task<LoginFailureResult> UpdateLoginFailure(int userId);
        Task<bool> UpdateLoginSuccess(int userId, bool markEmailVerified);
        Task<User> GetById(int userId, int tenantId);
        Task<string> GetPasswordHash(int userId, int tenantId);
        Task<bool> ChangePassword(int userId, int tenantId, string passwordHash);
        Task<long> CreateOtp(int tenantId, int userId, string purpose, string clientApp, string codeHash, DateTime expiresAt, string ipAddress);
        Task<OtpCode> GetOtpById(long otpId);
        Task<OtpCode> GetLatestOtp(int userId, string purpose);
        Task<int> CountOtpSince(int userId, string purpose, DateTime since);
        Task<int> IncrementOtpAttempts(long otpId);
        Task<bool> MarkOtpUsed(long otpId);
        Task<long> CreateSession(int userId, string refreshTokenHash, DateTime expiresAt, string deviceInfo, string ipAddress);
        Task<UserSession> GetSessionByHash(string refreshTokenHash);
        Task<long> RotateSession(long sessionId, string newRefreshTokenHash, DateTime newExpiresAt, string deviceInfo, string ipAddress);
        Task<bool> RevokeSession(int userId, string refreshTokenHash);
        Task<int> RevokeAllSessions(int userId, long? exceptSessionId);
        Task InsertAuditLog(AuditLog auditLog);
    }
    #endregion

    public class UserRepository : BaseRepository, IUserRepository
    {
        #region Constructor
        public UserRepository(IConfiguration configuration) : base(configuration)
        {
        }
        #endregion

        #region Authenticate
        public async Task<AuthenticateResult> Authenticate(string email, string tenantCode)
        {
            var data = new AuthenticateResult();
            using (var connection = CreateConnection())
            {
                var parameters = new DynamicParameters();
                parameters.Add("@Email", email);
                parameters.Add("@TenantCode", tenantCode);
                parameters.Add("@ReturnValue", dbType: DbType.Int32, direction: ParameterDirection.ReturnValue);

                connection.Open();
                var result = await connection.QueryFirstOrDefaultAsync<User>("[dbo].[User_Authenticate]", parameters, commandType: CommandType.StoredProcedure);

                data.ReturnValue = parameters.Get<int>("@ReturnValue");
                data.AuthunticateUser = result;
            }
            return data;
        }
        #endregion

        #region UpdateLoginFailure
        public async Task<LoginFailureResult> UpdateLoginFailure(int userId)
        {
            var data = new LoginFailureResult();
            using (var connection = CreateConnection())
            {
                var parameters = new DynamicParameters();
                parameters.Add("@UserId", userId);
                parameters.Add("@ReturnValue", dbType: DbType.Int32, direction: ParameterDirection.ReturnValue);

                connection.Open();
                var result = await connection.QueryFirstOrDefaultAsync<LoginFailureResult>("[dbo].[Users_UpdateLoginFailure]",
                    parameters,
                    commandType: CommandType.StoredProcedure);

                if (result != null)
                {
                    data = result;
                }
                data.ReturnValue = parameters.Get<int>("@ReturnValue");
            }
            return data;
        }
        #endregion

        #region UpdateLoginSuccess
        public async Task<bool> UpdateLoginSuccess(int userId, bool markEmailVerified)
        {
            using (var connection = CreateConnection())
            {
                var parameters = new DynamicParameters();
                parameters.Add("@UserId", userId);
                parameters.Add("@MarkEmailVerified", markEmailVerified);
                parameters.Add("@ReturnValue", dbType: DbType.Int32, direction: ParameterDirection.ReturnValue);

                connection.Open();
                await connection.ExecuteAsync("[dbo].[Users_UpdateLoginSuccess]", parameters, commandType: CommandType.StoredProcedure);

                return parameters.Get<int>("@ReturnValue") == 0;
            }
        }
        #endregion

        #region GetById
        public async Task<User> GetById(int userId, int tenantId)
        {
            User data = null;
            using (var connection = CreateConnection())
            {
                var parameters = new DynamicParameters();
                parameters.Add("@UserId", userId);
                parameters.Add("@TenantId", tenantId);
                parameters.Add("@ReturnValue", dbType: DbType.Int32, direction: ParameterDirection.ReturnValue);

                connection.Open();
                var result = await connection.QueryFirstOrDefaultAsync<User>("[dbo].[Users_GetById]",
                    parameters,
                    commandType: CommandType.StoredProcedure);

                if (parameters.Get<int>("@ReturnValue") == 0)
                {
                    data = result;
                }
            }
            return data;
        }
        #endregion

        #region GetPasswordHash
        public async Task<string> GetPasswordHash(int userId, int tenantId)
        {
            string data = null;
            using (var connection = CreateConnection())
            {
                var parameters = new DynamicParameters();
                parameters.Add("@UserId", userId);
                parameters.Add("@TenantId", tenantId);
                parameters.Add("@ReturnValue", dbType: DbType.Int32, direction: ParameterDirection.ReturnValue);

                connection.Open();
                var result = await connection.QueryFirstOrDefaultAsync<string>("[dbo].[Users_GetPasswordHash]",
                    parameters,
                    commandType: CommandType.StoredProcedure);

                if (parameters.Get<int>("@ReturnValue") == 0)
                {
                    data = result;
                }
            }
            return data;
        }
        #endregion

        #region ChangePassword
        public async Task<bool> ChangePassword(int userId, int tenantId, string passwordHash)
        {
            using (var connection = CreateConnection())
            {
                var parameters = new DynamicParameters();
                parameters.Add("@UserId", userId);
                parameters.Add("@TenantId", tenantId);
                parameters.Add("@PasswordHash", passwordHash);
                parameters.Add("@ReturnValue", dbType: DbType.Int32, direction: ParameterDirection.ReturnValue);

                connection.Open();
                await connection.ExecuteAsync("[dbo].[Users_ChangePassword]", parameters, commandType: CommandType.StoredProcedure);

                return parameters.Get<int>("@ReturnValue") == 0;
            }
        }
        #endregion

        #region CreateOtp
        public async Task<long> CreateOtp(int tenantId, int userId, string purpose, string clientApp, string codeHash, DateTime expiresAt, string ipAddress)
        {
            long data = 0;
            using (var connection = CreateConnection())
            {
                var parameters = new DynamicParameters();
                parameters.Add("@TenantId", tenantId);
                parameters.Add("@UserId", userId);
                parameters.Add("@Purpose", purpose);
                parameters.Add("@ClientApp", clientApp);
                parameters.Add("@CodeHash", codeHash);
                parameters.Add("@ExpiresAt", expiresAt, DbType.DateTime2);
                parameters.Add("@IPAddress", ipAddress);
                parameters.Add("@ReturnValue", dbType: DbType.Int32, direction: ParameterDirection.ReturnValue);

                connection.Open();
                var result = await connection.QueryFirstOrDefaultAsync<long>("[dbo].[OtpCodes_Create]",
                    parameters,
                    commandType: CommandType.StoredProcedure);

                if (parameters.Get<int>("@ReturnValue") == 0)
                {
                    data = result;
                }
            }
            return data;
        }
        #endregion

        #region GetOtpById
        public async Task<OtpCode> GetOtpById(long otpId)
        {
            OtpCode data = null;
            using (var connection = CreateConnection())
            {
                var parameters = new DynamicParameters();
                parameters.Add("@OtpId", otpId);
                parameters.Add("@ReturnValue", dbType: DbType.Int32, direction: ParameterDirection.ReturnValue);

                connection.Open();
                var result = await connection.QueryFirstOrDefaultAsync<OtpCode>("[dbo].[OtpCodes_GetById]",
                    parameters,
                    commandType: CommandType.StoredProcedure);

                if (parameters.Get<int>("@ReturnValue") == 0)
                {
                    data = result;
                }
            }
            return data;
        }
        #endregion

        #region GetLatestOtp
        public async Task<OtpCode> GetLatestOtp(int userId, string purpose)
        {
            OtpCode data = null;
            using (var connection = CreateConnection())
            {
                var parameters = new DynamicParameters();
                parameters.Add("@UserId", userId);
                parameters.Add("@Purpose", purpose);
                parameters.Add("@ReturnValue", dbType: DbType.Int32, direction: ParameterDirection.ReturnValue);

                connection.Open();
                var result = await connection.QueryFirstOrDefaultAsync<OtpCode>("[dbo].[OtpCodes_GetLatest]",
                    parameters,
                    commandType: CommandType.StoredProcedure);

                if (parameters.Get<int>("@ReturnValue") == 0)
                {
                    data = result;
                }
            }
            return data;
        }
        #endregion

        #region CountOtpSince
        public async Task<int> CountOtpSince(int userId, string purpose, DateTime since)
        {
            using (var connection = CreateConnection())
            {
                var parameters = new DynamicParameters();
                parameters.Add("@UserId", userId);
                parameters.Add("@Purpose", purpose);
                parameters.Add("@Since", since, DbType.DateTime2);

                connection.Open();
                var result = await connection.QueryFirstOrDefaultAsync<int>("[dbo].[OtpCodes_CountSince]",
                    parameters,
                    commandType: CommandType.StoredProcedure);

                return result;
            }
        }
        #endregion

        #region IncrementOtpAttempts
        public async Task<int> IncrementOtpAttempts(long otpId)
        {
            int data = 0;
            using (var connection = CreateConnection())
            {
                var parameters = new DynamicParameters();
                parameters.Add("@OtpId", otpId);
                parameters.Add("@ReturnValue", dbType: DbType.Int32, direction: ParameterDirection.ReturnValue);

                connection.Open();
                var result = await connection.QueryFirstOrDefaultAsync<int>("[dbo].[OtpCodes_IncrementAttempts]",
                    parameters,
                    commandType: CommandType.StoredProcedure);

                if (parameters.Get<int>("@ReturnValue") == 0)
                {
                    data = result;
                }
            }
            return data;
        }
        #endregion

        #region MarkOtpUsed
        public async Task<bool> MarkOtpUsed(long otpId)
        {
            using (var connection = CreateConnection())
            {
                var parameters = new DynamicParameters();
                parameters.Add("@OtpId", otpId);
                parameters.Add("@ReturnValue", dbType: DbType.Int32, direction: ParameterDirection.ReturnValue);

                connection.Open();
                await connection.ExecuteAsync("[dbo].[OtpCodes_MarkUsed]", parameters, commandType: CommandType.StoredProcedure);

                return parameters.Get<int>("@ReturnValue") == 0;
            }
        }
        #endregion

        #region CreateSession
        public async Task<long> CreateSession(int userId, string refreshTokenHash, DateTime expiresAt, string deviceInfo, string ipAddress)
        {
            long data = 0;
            using (var connection = CreateConnection())
            {
                var parameters = new DynamicParameters();
                parameters.Add("@UserId", userId);
                parameters.Add("@RefreshTokenHash", refreshTokenHash);
                parameters.Add("@ExpiresAt", expiresAt, DbType.DateTime2);
                parameters.Add("@DeviceInfo", deviceInfo);
                parameters.Add("@IPAddress", ipAddress);
                parameters.Add("@ReturnValue", dbType: DbType.Int32, direction: ParameterDirection.ReturnValue);

                connection.Open();
                var result = await connection.QueryFirstOrDefaultAsync<long>("[dbo].[UserSessions_Create]",
                    parameters,
                    commandType: CommandType.StoredProcedure);

                if (parameters.Get<int>("@ReturnValue") == 0)
                {
                    data = result;
                }
            }
            return data;
        }
        #endregion

        #region GetSessionByHash
        public async Task<UserSession> GetSessionByHash(string refreshTokenHash)
        {
            var data = new UserSession();
            using (var connection = CreateConnection())
            {
                var parameters = new DynamicParameters();
                parameters.Add("@RefreshTokenHash", refreshTokenHash);
                parameters.Add("@ReturnValue", dbType: DbType.Int32, direction: ParameterDirection.ReturnValue);

                connection.Open();
                var result = await connection.QueryFirstOrDefaultAsync<UserSession>("[dbo].[UserSessions_GetByHash]",
                    parameters,
                    commandType: CommandType.StoredProcedure);

                if (result != null)
                {
                    data = result;
                }
                data.ReturnValue = parameters.Get<int>("@ReturnValue");
            }
            return data;
        }
        #endregion

        #region RotateSession
        public async Task<long> RotateSession(long sessionId, string newRefreshTokenHash, DateTime newExpiresAt, string deviceInfo, string ipAddress)
        {
            long data = 0;
            using (var connection = CreateConnection())
            {
                var parameters = new DynamicParameters();
                parameters.Add("@SessionId", sessionId);
                parameters.Add("@NewRefreshTokenHash", newRefreshTokenHash);
                parameters.Add("@NewExpiresAt", newExpiresAt, DbType.DateTime2);
                parameters.Add("@DeviceInfo", deviceInfo);
                parameters.Add("@IPAddress", ipAddress);
                parameters.Add("@ReturnValue", dbType: DbType.Int32, direction: ParameterDirection.ReturnValue);

                connection.Open();
                var result = await connection.QueryFirstOrDefaultAsync<long>("[dbo].[UserSessions_Rotate]",
                    parameters,
                    commandType: CommandType.StoredProcedure);

                if (parameters.Get<int>("@ReturnValue") == 0)
                {
                    data = result;
                }
            }
            return data;
        }
        #endregion

        #region RevokeSession
        public async Task<bool> RevokeSession(int userId, string refreshTokenHash)
        {
            using (var connection = CreateConnection())
            {
                var parameters = new DynamicParameters();
                parameters.Add("@UserId", userId);
                parameters.Add("@RefreshTokenHash", refreshTokenHash);
                parameters.Add("@ReturnValue", dbType: DbType.Int32, direction: ParameterDirection.ReturnValue);

                connection.Open();
                await connection.ExecuteAsync("[dbo].[UserSessions_Revoke]", parameters, commandType: CommandType.StoredProcedure);

                return parameters.Get<int>("@ReturnValue") == 0;
            }
        }
        #endregion

        #region RevokeAllSessions
        public async Task<int> RevokeAllSessions(int userId, long? exceptSessionId)
        {
            using (var connection = CreateConnection())
            {
                var parameters = new DynamicParameters();
                parameters.Add("@UserId", userId);
                parameters.Add("@ExceptSessionId", exceptSessionId, DbType.Int64);

                connection.Open();
                var result = await connection.QueryFirstOrDefaultAsync<int>("[dbo].[UserSessions_RevokeAll]",
                    parameters,
                    commandType: CommandType.StoredProcedure);

                return result;
            }
        }
        #endregion

        #region InsertAuditLog
        public async Task InsertAuditLog(AuditLog auditLog)
        {
            using (var connection = CreateConnection())
            {
                var parameters = new DynamicParameters();
                parameters.Add("@TenantId", auditLog.TenantId);
                parameters.Add("@UserId", auditLog.UserId, DbType.Int32);
                parameters.Add("@ModuleId", auditLog.ModuleId, DbType.Int32);
                parameters.Add("@ActionType", auditLog.ActionType);
                parameters.Add("@TableName", auditLog.TableName);
                parameters.Add("@RecordId", auditLog.RecordId);
                parameters.Add("@OldValues", auditLog.OldValues);
                parameters.Add("@NewValues", auditLog.NewValues);
                parameters.Add("@IPAddress", auditLog.IPAddress);
                parameters.Add("@UserAgent", auditLog.UserAgent);

                connection.Open();
                await connection.ExecuteAsync("[dbo].[AuditLogs_Insert]", parameters, commandType: CommandType.StoredProcedure);
            }
        }
        #endregion
    }
}