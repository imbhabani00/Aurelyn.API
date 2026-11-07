using Aurelyn.Domain.Token;
using FluentValidation;

namespace Aurelyn.Application.Validators
{
    public class RefreshTokenModelValidator : AbstractValidator<RefreshTokenModel>
    {
        public RefreshTokenModelValidator()
        {
            RuleFor(x => x.AccessToken)
                .NotEmpty().WithMessage("Access token is required.");

            RuleFor(x => x.RefreshToken)
                .NotEmpty().WithMessage("Refresh token is required.");
        }
    }
}
