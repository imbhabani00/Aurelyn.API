using Aurelyn.Domain.Constants;
using Aurelyn.Domain.Settings;
using MailKit.Security;
using Microsoft.Extensions.Logging;
using MimeKit;
using System.Net;

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
        private readonly EmailSettings _emailSettings;
        private readonly ILogger<OtpService> _logger;
        #endregion

        #region Constructor
        public OtpService(EmailSettings emailSettings, ILogger<OtpService> logger)
        {
            _emailSettings = emailSettings;
            _logger = logger;
        }
        #endregion

        #region SendOtpAsync
        public async Task SendOtpAsync(string email, string code, string purpose, int expiryMinutes)
        {
            try
            {
                var message = new MimeMessage();
                message.From.Add(new MailboxAddress(_emailSettings.FromName, _emailSettings.FromEmail));
                message.To.Add(MailboxAddress.Parse(email));
                message.Subject = GetSubject(purpose);

                var builder = new BodyBuilder
                {
                    HtmlBody = BuildHtmlBody(code, purpose, expiryMinutes),
                    TextBody = $"Your verification code is {code}. It is valid for {expiryMinutes} minutes. If you did not request it, ignore this email."
                };
                message.Body = builder.ToMessageBody();

                var secureOption = _emailSettings.Port == 465
                    ? SecureSocketOptions.SslOnConnect
                    : _emailSettings.EnableSsl ? SecureSocketOptions.StartTls : SecureSocketOptions.None;

                using var client = new MailKit.Net.Smtp.SmtpClient();
                await client.ConnectAsync(_emailSettings.Host, _emailSettings.Port, secureOption);

                if (!string.IsNullOrWhiteSpace(_emailSettings.Username))
                {
                    await client.AuthenticateAsync(_emailSettings.Username, _emailSettings.Password);
                }

                await client.SendAsync(message);
                await client.DisconnectAsync(true);

                // never log the code itself
                _logger.LogInformation("SendOtpAsync: OTP email sent - Purpose: {Purpose}", purpose);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SendOtpAsync: Failed to send OTP email - Purpose: {Purpose}", purpose);
                throw;
            }
        }
        #endregion

        #region Helpers
        private static string GetSubject(string purpose)
        {
            switch (purpose)
            {
                case OtpPurposeConstant.Register:
                    return "Verify your email - Aurelyn Care";
                case OtpPurposeConstant.PasswordReset:
                    return "Reset your password - Aurelyn Care";
                default:
                    return "Your sign-in code - Aurelyn Care";
            }
        }

        private static string BuildHtmlBody(string code, string purpose, int expiryMinutes)
        {
            var title = purpose == OtpPurposeConstant.Register ? "Verify your email"
                      : purpose == OtpPurposeConstant.PasswordReset ? "Reset your password"
                      : "Sign in to Aurelyn Care";

            return $@"
                        <div style=""font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px;border:1px solid #e5e7eb;border-radius:8px"">
                          <h2 style=""margin:0 0 12px 0;color:#111827"">{WebUtility.HtmlEncode(title)}</h2>
                          <p style=""color:#374151"">Use this code to continue:</p>
                          <p style=""font-size:32px;font-weight:bold;letter-spacing:6px;margin:16px 0;color:#111827"">{WebUtility.HtmlEncode(code)}</p>
                          <p style=""color:#374151"">It is valid for {expiryMinutes} minutes. Do not share it with anyone.</p>
                          <p style=""color:#6b7280;font-size:12px"">If you did not request this code, you can ignore this email.</p>
                        </div>";
        }
        #endregion
    }
}