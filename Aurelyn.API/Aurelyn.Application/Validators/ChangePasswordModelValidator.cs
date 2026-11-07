using Aurelyn.Domain.Authuntication;
using FluentValidation;

namespace Aurelyn.Application.Validators
{
    public class ChangePasswordModelValidator : AbstractValidator<ChangePasswordModel>
    {
        public ChangePasswordModelValidator()
        {
            RuleFor(x => x.CurrentPassword)
                .NotEmpty().WithMessage("Current password is required.");

            RuleFor(x => x.NewPassword)
                .Cascade(CascadeMode.Stop)
                .NotEmpty().WithMessage("New password is required.")
                .MinimumLength(8).WithMessage("New password must be at least 8 characters.")
                .MaximumLength(72).WithMessage("New password must not exceed 72 characters.")
                .Matches("[A-Z]").WithMessage("New password must contain an upper case letter.")
                .Matches("[a-z]").WithMessage("New password must contain a lower case letter.")
                .Matches("[0-9]").WithMessage("New password must contain a number.")
                .Matches("[^a-zA-Z0-9]").WithMessage("New password must contain a special character.")
                .NotEqual(x => x.CurrentPassword).WithMessage("New password must be different from the current password.");

            RuleFor(x => x.ConfirmPassword)
                .Cascade(CascadeMode.Stop)
                .NotEmpty().WithMessage("Confirm password is required.")
                .Equal(x => x.NewPassword).WithMessage("New password and confirm password do not match.");
        }
    }
}
