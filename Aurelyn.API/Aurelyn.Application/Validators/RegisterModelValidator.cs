using Aurelyn.Domain.Models.Authuntication;
using FluentValidation;

namespace Aurelyn.Application.Validators
{
    public class RegisterModelValidator : AbstractValidator<Register>
    {
        public RegisterModelValidator()
        {
            RuleFor(x => x.FirstName)
                .NotEmpty().WithMessage("First name is required.")
                .MaximumLength(100).WithMessage("First name must not exceed 100 characters.");

            RuleFor(x => x.LastName)
                .MaximumLength(100).WithMessage("Last name must not exceed 100 characters.");

            RuleFor(x => x.Email)
                .Cascade(CascadeMode.Stop)
                .NotEmpty().WithMessage("Email is required.")
                .MaximumLength(256).WithMessage("Email must not exceed 256 characters.")
                .EmailAddress().WithMessage("Email is not valid.");

            RuleFor(x => x.Password).Cascade(CascadeMode.Stop).MustBeStrongPassword();

            RuleFor(x => x.ConfirmPassword)
                .Cascade(CascadeMode.Stop)
                .NotEmpty().WithMessage("Confirm password is required.")
                .Equal(x => x.Password).WithMessage("Password and confirm password do not match.");

            RuleFor(x => x.TenantCode)
                .MaximumLength(50).WithMessage("Tenant code must not exceed 50 characters.");

            RuleFor(x => x.ClientApp)
                .MaximumLength(30).WithMessage("Client app must not exceed 30 characters.");
        }
    }
}
