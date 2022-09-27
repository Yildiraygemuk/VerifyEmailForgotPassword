namespace VerifyEmailForgotPassword.Service
{
    public interface IUserService
    {
        string? Register(UserRegisterRequest request);
        string? Login(UserLoginRequest request);
        string? Verify(string token);
        string? ForgotPassword(string email);
        string? ResetPassword(ResetPasswordRequest request);
    }
}
