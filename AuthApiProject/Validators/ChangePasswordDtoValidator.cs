using AuthApiProject.DTOs;
using FluentValidation;

namespace AuthApiProject.Validators
{
    public class ChangePasswordDtoValidator : AbstractValidator<ChangePasswordDto>
    {

        public ChangePasswordDtoValidator()
        {
            RuleFor(x => x.CurrentPassword).NotEmpty().WithMessage("Current password is required");
            RuleFor(x => x.NewPassword)
                .NotEmpty()
                .MinimumLength(8).WithMessage("New password must be at least 8 characters")
                .Matches("[A-Z]").WithMessage("New password must contain at least one uppercase letter")
                .Matches("[a-z]").WithMessage("New password must contain at least one lowercase letter")
                .Matches("[0-9]").WithMessage("New password must contain at least one number");
        }


    }
}
