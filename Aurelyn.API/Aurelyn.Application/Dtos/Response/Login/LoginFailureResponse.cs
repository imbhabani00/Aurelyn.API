namespace Aurelyn.Application.Dtos.Response.Login
{
    public class LoginFailureResponse
    {
        public int FailedLoginAttempts { get; set; }
        public DateTime? LockedUntil { get; set; }
        public int ReturnValue { get; set; }
    }
}
