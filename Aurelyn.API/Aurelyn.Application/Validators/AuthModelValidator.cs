using Aurelyn.Domain.Authuntication;
using FluentValidation;

namespace Aurelyn.Application.Validators
{
    public class AuthModelValidator : AbstractValidator<AuthModel>
    {
        public AuthModelValidator() 
        {
            RuleFor(x => x.Email)
                .Cascade(CascadeMode.Stop)
                .NotEmpty().WithMessage("Email is required.")
                .MaximumLength(256).WithMessage("Email must not exceed 256 characters.")
                .EmailAddress().WithMessage("Email is not valid.");

            RuleFor(x => x.Password)
                .Cascade(CascadeMode.Stop)
                .NotEmpty().WithMessage("Password is required.")
                .MaximumLength(72).WithMessage("Password must not exceed 72 characters.");

            RuleFor(x => x.TenantCode)
                .MaximumLength(50).WithMessage("Tenant code must not exceed 50 characters.");

            RuleFor(x => x.ClientApp)
                .MaximumLength(30).WithMessage("Client app must not exceed 30 characters.");
        }
    }
}