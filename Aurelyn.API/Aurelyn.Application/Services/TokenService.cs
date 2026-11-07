using Aurelyn.Domain.Settings;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Aurelyn.Application.Services
{
    #region Interface
    public interface ITokenService
    {
        string GenerateAccessToken(IEnumerable<Claim> claims);
        string GenerateRefreshToken();
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
        string HashToken(string token);
        string GenerateOtp();
        string HashOtp(int userId, string purpose, string code);
        bool VerifyOtp(int userId, string purpose, string code, string codeHash);
    }
    #endregion

    public class TokenService : ITokenService
    {
        #region Properties
        private readonly JwtSettings _jwtSettings;
        #endregion

        #region Constructor
        public TokenService(IOptions<JwtSettings> jwtSettings)
        {
            _jwtSettings = jwtSettings.Value;
        }
        #endregion

        #region GenerateAccessToken
        public string GenerateAccessToken(IEnumerable<Claim> claims)
        {
            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Issuer = _jwtSettings.Issuer,
                Audience = _jwtSettings.Audience,
                Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpiryMinutes),
                SigningCredentials = new SigningCredentials(
                    key, SecurityAlgorithms.HmacSha256)
            };

            var handler = new JwtSecurityTokenHandler();
            var token = handler.CreateToken(tokenDescriptor);
            return handler.WriteToken(token);
        }
        #endregion

        #region GenerateRefreshToken
        public string GenerateRefreshToken()
        {
            var randomBytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            return Convert.ToBase64String(randomBytes);
        }
        #endregion

        #region GetPrincipalFromExpiredToken
        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                throw new SecurityTokenException("Invalid token");
            }

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));

            var validationParams = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _jwtSettings.Issuer,
                ValidAudience = _jwtSettings.Audience,
                IssuerSigningKey = key,
                ValidateLifetime = false
            };

            var handler = new JwtSecurityTokenHandler();
            ClaimsPrincipal principal;
            SecurityToken securityToken;

            try
            {
                principal = handler.ValidateToken(token, validationParams, out securityToken);
            }
            catch (ArgumentException)
            {
                // malformed token strings surface as ArgumentException
                throw new SecurityTokenException("Invalid token");
            }

            // Validate it's actually HmacSha256
            if (securityToken is not JwtSecurityToken jwtToken ||
                !jwtToken.Header.Alg.Equals(
                    SecurityAlgorithms.HmacSha256,
                    StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }

            return principal;
        }
        #endregion

        #region HashToken
        // Refresh tokens are 64 random bytes, so a plain SHA-256 is enough.
        // Only this hash is stored in tbl_UserSessions.
        public string HashToken(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                throw new ArgumentException("Token is required", nameof(token));
            }

            var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(token));
            return Convert.ToHexString(bytes);
        }
        #endregion

        #region GenerateOtp
        public string GenerateOtp()
        {
            var code = RandomNumberGenerator.GetInt32(0, 1_000_000);
            return code.ToString("D6");
        }
        #endregion

        #region HashOtp
        // A 6 digit code is easy to brute force if the hash leaks, so it is
        // hashed with HMAC and the server secret (plus user and purpose).
        public string HashOtp(int userId, string purpose, string code)
        {
            var keyBytes = Encoding.UTF8.GetBytes(_jwtSettings.SecretKey);
            var data = Encoding.UTF8.GetBytes($"{userId}:{purpose}:{code}");
            var hash = HMACSHA256.HashData(keyBytes, data);
            return Convert.ToHexString(hash);
        }
        #endregion

        #region VerifyOtp
        public bool VerifyOtp(int userId, string purpose, string code, string codeHash)
        {
            if (string.IsNullOrWhiteSpace(code) || string.IsNullOrEmpty(codeHash))
            {
                return false;
            }

            var expected = Encoding.UTF8.GetBytes(HashOtp(userId, purpose, code));
            var actual = Encoding.UTF8.GetBytes(codeHash);
            return CryptographicOperations.FixedTimeEquals(expected, actual);
        }
        #endregion
    }
}