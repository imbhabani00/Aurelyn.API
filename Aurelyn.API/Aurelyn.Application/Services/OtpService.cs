using Microsoft.Extensions.Logging;

namespace Aurelyn.Application.Services
{
    #region Interface
    public interface IOtpService
    {
        Task SendOtpAsync(string email, string code, string purpose, int expiryMinutes);
    }
    #endregion

    public class OtpService : IOtpService
    { 
        
        #region Properties
        private readonly ILogger<OtpService> _logger;
        #endregion

        #region Constructor
        public OtpService(ILogger<OtpService> logger)
        {
            _logger = logger;
        }
        #endregion

        #region SendOtpAsync
        public Task SendOtpAsync(string email, string code, string purpose, int expiryMinutes)
        {
            _logger.LogWarning("DEV OTP for {Email} ({Purpose}): {Code} - valid for {Minutes} minutes", email, purpose, code, expiryMinutes);
            return Task.CompletedTask;
        }
        #endregion
    }
}