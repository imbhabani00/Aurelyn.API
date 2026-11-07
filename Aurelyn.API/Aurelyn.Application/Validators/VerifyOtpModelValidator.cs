using Aurelyn.Domain.Otp;
using FluentValidation;

namespace Aurelyn.Application.Validators
{
    public class VerifyOtpModelValidator : AbstractValidator<VerifyOtpModel>
    {
        public VerifyOtpModelValidator()
        {
            RuleFor(x => x.OtpId)
                .GreaterThan(0).WithMessage("OtpId is required.");

            RuleFor(x => x.Code)
                .Cascade(CascadeMode.Stop)
                .NotEmpty().WithMessage("OTP code is required.")
                .Matches(@"^\d{6}$").WithMessage("OTP code must be 6 digits.");
        }
    }
}
