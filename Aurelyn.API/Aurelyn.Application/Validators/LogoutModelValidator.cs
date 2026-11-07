using Aurelyn.Domain.Models.Authuntication;
using FluentValidation;

namespace Aurelyn.Application.Validators
{
    public class LogoutModelValidator : AbstractValidator<LogoutModel>
    {
        public LogoutModelValidator()
        {
            RuleFor(x => x.RefreshToken)
                .NotEmpty().WithMessage("Refresh token is required.");
        }
    }
}
