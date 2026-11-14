using Aurelyn.Domain.Otp;
using FluentValidation;

namespace Aurelyn.Application.Validators
{
    public class ResendOtpModelValidator : AbstractValidator<ResendOtpModel>
    {
        public ResendOtpModelValidator()
        {
            RuleFor(x => x.OtpId)
                .GreaterThan(0).WithMessage("OtpId is required.");
        }
    }
}
