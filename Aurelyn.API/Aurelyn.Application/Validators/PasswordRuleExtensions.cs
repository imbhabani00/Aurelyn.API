using FluentValidation;

namespace Aurelyn.Application.Validators
{
    public static class PasswordRuleExtensions
    {
        public static IRuleBuilderOptions<T, string> MustBeStrongPassword<T>(this IRuleBuilder<T, string> rule)
        {
            return rule
                .NotEmpty().WithMessage("Password is required.")
                .MinimumLength(8).WithMessage("Password must be at least 8 characters.")
                .MaximumLength(72).WithMessage("Password must not exceed 72 characters.")
                .Matches("[A-Z]").WithMessage("Password must contain an upper case letter.")
                .Matches("[a-z]").WithMessage("Password must contain a lower case letter.")
                .Matches("[0-9]").WithMessage("Password must contain a number.")
                .Matches("[^a-zA-Z0-9]").WithMessage("Password must contain a special character.");
        }
    }
}
