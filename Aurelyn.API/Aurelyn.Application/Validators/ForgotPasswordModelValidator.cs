using Aurelyn.Domain.Models.Authuntication;
using FluentValidation;

namespace Aurelyn.Application.Validators
{
    public class ForgotPasswordModelValidator : AbstractValidator<ForgotPassword>
    {
        public ForgotPasswordModelValidator()
        {
            RuleFor(x => x.Email)
                .Cascade(CascadeMode.Stop)
                .NotEmpty().WithMessage("Email is required.")
                .MaximumLength(256).WithMessage("Email must not exceed 256 characters.")
                .EmailAddress().WithMessage("Email is not valid.");

            RuleFor(x => x.TenantCode)
                .MaximumLength(50).WithMessage("Tenant code must not exceed 50 characters.");
        }
    }
}
