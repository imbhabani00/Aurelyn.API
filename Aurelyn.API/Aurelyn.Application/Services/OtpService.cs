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

        // ===== Aurelyn Care - Login Page Color Theme =====
        private const string ColorPageBg = "#090d19";    // Outer dark background
        private const string ColorCardBg = "#151f35";    // OTP email card
        private const string ColorCodeBg = "#0c1427";    // OTP code background
        private const string ColorBorder = "#34446f";    // Card and input borders
        private const string ColorAccent = "#7568f6";    // Primary purple
        private const string ColorAccentDark = "#5549dc"; // Dark purple
        private const string ColorAccentLight = "#aaa0ff"; // Light lavender
        private const string ColorTextMain = "#f8f8ff";  // Main headings
        private const string ColorTextBody = "#c4c9ee";  // Normal text
        private const string ColorTextMute = "#8b91b8";  // Footer text

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

            var intro = purpose == OtpPurposeConstant.Register
                      ? "Welcome to Aurelyn Care. Enter this code to confirm your email address and finish creating your account."
                      : purpose == OtpPurposeConstant.PasswordReset
                      ? "We received a request to reset your password. Enter this code to continue."
                      : "Enter this code to finish signing in to your account.";

            // Spaced digits are easier to read, e.g. 482 913
            var displayCode = code.Length == 6
                ? $"{code.Substring(0, 3)} {code.Substring(3)}"
                : code;

                 return $@"
                            <!DOCTYPE html>
                            <html lang=""en"">
                            <head>
                                <meta charset=""utf-8"">
                                <meta name=""viewport"" content=""width=device-width, initial-scale=1"">
                                <meta name=""color-scheme"" content=""dark"">
                                <meta name=""supported-color-schemes"" content=""dark"">
                            </head>

                            <body style=""
                                margin:0;
                                padding:0;
                                background-color:{ColorPageBg};
                            "">
                                <table role=""presentation"" width=""100%"" cellpadding=""0"" cellspacing=""0""
                                       border=""0"" bgcolor=""{ColorPageBg}""
                                       style=""background-color:{ColorPageBg};"">

                                    <tr>
                                        <td align=""center"" style=""padding:32px 16px;"">

                                            <table role=""presentation"" width=""100%"" cellpadding=""0""
                                                   cellspacing=""0"" border=""0""
                                                   style=""max-width:520px;"">

                                                <!-- Brand -->
                                                <tr>
                                                    <td align=""center""
                                                        style=""
                                                            padding:0 0 20px 0;
                                                            font-family:Arial,Helvetica,sans-serif;
                                                            font-size:22px;
                                                            font-weight:bold;
                                                            letter-spacing:0.5px;
                                                            color:{ColorTextMain};
                                                        "">

                                                        <span style=""color:{ColorAccent};"">&#9679;</span>
                                                        &nbsp;Aurelyn Care

                                                        <div style=""
                                                            padding-top:5px;
                                                            font-size:12px;
                                                            font-weight:normal;
                                                            letter-spacing:0;
                                                            color:{ColorTextMute};
                                                        "">
                                                            Your Health, Our Priority
                                                        </div>
                                                    </td>
                                                </tr>

                                                <!-- Card -->
                                                <tr>
                                                    <td bgcolor=""{ColorCardBg}""
                                                        style=""
                                                            background-color:{ColorCardBg};
                                                            border:1px solid {ColorBorder};
                                                            border-radius:18px;
                                                            overflow:hidden;
                                                        "">

                                                        <!-- Purple Accent Bar -->
                                                        <table role=""presentation"" width=""100%""
                                                               cellpadding=""0"" cellspacing=""0"" border=""0"">
                                                            <tr>
                                                                <td height=""5""
                                                                    bgcolor=""{ColorAccent}""
                                                                    style=""
                                                                        background-color:{ColorAccent};
                                                                        font-size:0;
                                                                        line-height:0;
                                                                    "">
                                                                    &nbsp;
                                                                </td>
                                                            </tr>
                                                        </table>

                                                        <table role=""presentation"" width=""100%""
                                                               cellpadding=""0"" cellspacing=""0"" border=""0"">

                                                            <!-- Heading -->
                                                            <tr>
                                                                <td style=""
                                                                    padding:32px 32px 8px 32px;
                                                                    font-family:Arial,Helvetica,sans-serif;
                                                                "">

                                                                    <h1 style=""
                                                                        margin:0 0 12px 0;
                                                                        font-size:25px;
                                                                        line-height:1.3;
                                                                        color:{ColorTextMain};
                                                                    "">
                                                                        {WebUtility.HtmlEncode(title)}
                                                                    </h1>

                                                                    <p style=""
                                                                        margin:0;
                                                                        font-size:15px;
                                                                        line-height:1.7;
                                                                        color:{ColorTextBody};
                                                                    "">
                                                                        {WebUtility.HtmlEncode(intro)}
                                                                    </p>

                                                                </td>
                                                            </tr>

                                                            <!-- OTP Code -->
                                                            <tr>
                                                                <td align=""center""
                                                                    style=""padding:28px 32px;"">

                                                                    <table role=""presentation""
                                                                           cellpadding=""0""
                                                                           cellspacing=""0""
                                                                           border=""0"">

                                                                        <tr>
                                                                            <td align=""center""
                                                                                bgcolor=""{ColorCodeBg}""
                                                                                style=""
                                                                                    background-color:{ColorCodeBg};
                                                                                    border:1px solid {ColorAccent};
                                                                                    border-radius:14px;
                                                                                    padding:20px 34px;
                                                                                    font-family:'Courier New',Courier,monospace;
                                                                                    font-size:36px;
                                                                                    font-weight:bold;
                                                                                    letter-spacing:8px;
                                                                                    color:{ColorAccentLight};
                                                                                "">

                                                                                {WebUtility.HtmlEncode(displayCode)}

                                                                            </td>
                                                                        </tr>

                                                                    </table>
                                                                </td>
                                                            </tr>

                                                            <!-- Expiry and Security -->
                                                            <tr>
                                                                <td style=""
                                                                    padding:0 32px 28px 32px;
                                                                    font-family:Arial,Helvetica,sans-serif;
                                                                "">

                                                                    <p style=""
                                                                        margin:0 0 10px 0;
                                                                        font-size:14px;
                                                                        line-height:1.6;
                                                                        color:{ColorTextBody};
                                                                    "">
                                                                        This code is valid for
                                                                        <strong style=""color:{ColorAccentLight};"">
                                                                            {expiryMinutes} minutes
                                                                        </strong>.
                                                                    </p>

                                                                    <p style=""
                                                                        margin:0;
                                                                        font-size:14px;
                                                                        line-height:1.6;
                                                                        color:{ColorTextBody};
                                                                    "">
                                                                        For your security, never share this code
                                                                        with anyone. Aurelyn Care staff will
                                                                        never ask for it.
                                                                    </p>

                                                                </td>
                                                            </tr>

                                                            <!-- Divider -->
                                                            <tr>
                                                                <td style=""padding:0 32px;"">
                                                                    <div style=""
                                                                        height:1px;
                                                                        background-color:{ColorBorder};
                                                                        line-height:1px;
                                                                        font-size:1px;
                                                                    "">
                                                                        &nbsp;
                                                                    </div>
                                                                </td>
                                                            </tr>

                                                            <!-- Notice -->
                                                            <tr>
                                                                <td style=""
                                                                    padding:18px 32px 28px 32px;
                                                                    font-family:Arial,Helvetica,sans-serif;
                                                                    font-size:12px;
                                                                    line-height:1.7;
                                                                    color:{ColorTextMute};
                                                                "">

                                                                    If you did not request this code,
                                                                    you can safely ignore this email.
                                                                    Your account stays secure.

                                                                </td>
                                                            </tr>

                                                        </table>

                                                    </td>
                                                </tr>

                                                <!-- Footer -->
                                                <tr>
                                                    <td align=""center""
                                                        style=""
                                                            padding:22px 8px 0 8px;
                                                            font-family:Arial,Helvetica,sans-serif;
                                                            font-size:12px;
                                                            line-height:1.7;
                                                            color:{ColorTextMute};
                                                        "">

                                                        &copy; {DateTime.UtcNow.Year} Aurelyn Care.
                                                        All rights reserved.

                                                        <br>

                                                        This is an automated message, please do not reply.
                                                             <!-- Founder Credit -->
                                                             <p style=""
                                                                 margin:0;
                                                                 padding:12px 10px;
                                                                 text-align:center;
                                                                 font-family:Arial,Helvetica,sans-serif;
                                                                 font-size:12px;
                                                                 color:{ColorTextMute};
                                                             "">
                                                                 Founded by
                                                                 <a href=""https://www.linkedin.com/in/bhabanishankar-mishra-9537a6326/""
                                                                    target=""_blank""
                                                                    style=""color:{ColorAccentLight};font-weight:bold;text-decoration:none;"">
                                                                     BhabaniShankar
                                                                 </a> |
                                                                 <a href=""https://www.instagram.com/i.m.bhabani/""
                                                                    target=""_blank""
                                                                    style=""color:{ColorAccentLight};font-weight:bold;text-decoration:none;"">
                                                                     Instagram
                                                                 </a>
                                                             </p>
                                                    </td>
                                                </tr>

                                            </table>

                                        </td>
                                    </tr>

                                </table>

                            </body>
                            </html>";
        }

        #endregion
    }
}