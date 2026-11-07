using Aurelyn.Domain.Models.Authuntication;
using FluentValidation;

namespace Aurelyn.Application.Validators
{
    public class ResetPasswordModelValidator : AbstractValidator<ResetPassword>
    {
        public ResetPasswordModelValidator()
        {
            RuleFor(x => x.Email)
                .Cascade(CascadeMode.Stop)
                .NotEmpty().WithMessage("Email is required.")
                .MaximumLength(256).WithMessage("Email must not exceed 256 characters.")
                .EmailAddress().WithMessage("Email is not valid.");

            RuleFor(x => x.TenantCode)
                .MaximumLength(50).WithMessage("Tenant code must not exceed 50 characters.");

            RuleFor(x => x.Code)
                .Cascade(CascadeMode.Stop)
                .NotEmpty().WithMessage("Code is required.")
                .Matches(@"^\d{6}$").WithMessage("Code must be 6 digits.");

            RuleFor(x => x.NewPassword).Cascade(CascadeMode.Stop).MustBeStrongPassword();

            RuleFor(x => x.ConfirmPassword)
                .Cascade(CascadeMode.Stop)
                .NotEmpty().WithMessage("Confirm password is required.")
                .Equal(x => x.NewPassword).WithMessage("New password and confirm password do not match.");
        }
    }

}
