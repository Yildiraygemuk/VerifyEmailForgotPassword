using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace VerifyEmailForgotPassword.Service
{
   
    public class UserService : IUserService
    {
        private readonly DataContext _context;
        public UserService(DataContext context)
        {
            _context = context;
        }
        public string? Register(UserRegisterRequest request)
        {
            if (_context.Users.Any(u => u.Email == request.Email))
            {
                return null;
            }
            CreatePasswordHash(request.Password,
                 out byte[] passwordHash,
                 out byte[] passwordSalt);
            var user = new User
            {
                Email = request.Email,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt,
                VerificationToken = CreateRandomToken()
            };
            _context.Users.Add(user);
            _context.SaveChanges();
            return "User successfully created!";
        }
        public string? Login(UserLoginRequest request)
        {
            var user = _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email).Result;
            if (user == null || !VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt) || user.VerifiedAt == null)
            {
                return null;
            }

            return $"Welcome back, {user.Email}! :)";
        }
        public string? Verify(string token)
        {
            var user =  _context.Users.FirstOrDefaultAsync(u => u.VerificationToken == token)?.Result;
            if (user == null)
            {
                return null;
            }

            user.VerifiedAt = DateTime.Now;
            _context.SaveChanges();

            return "User verified! :)";
        }
        public string? ForgotPassword(string email)
        {
            var user = _context.Users.FirstOrDefaultAsync(u => u.Email == email)?.Result;
            if (user == null)
            {
                return null;
            }

            user.PasswordResetToken = CreateRandomToken();
            user.ResetTokenExpires = DateTime.Now.AddDays(1);
            _context.SaveChanges();

            return "You may now reset your password.";
        }
        public string? ResetPassword(ResetPasswordRequest request)
        {
            var user = _context.Users.FirstOrDefaultAsync(u => u.PasswordResetToken == request.Token).Result;
            if (user == null || user.ResetTokenExpires < DateTime.Now)
            {
                return null;
            }

            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            user.PasswordResetToken = null;
            user.ResetTokenExpires = null;

            _context.SaveChanges();

            return "Password successfully reset.";
        }
        private string CreateRandomToken()
        {
            return Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
        }
        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac
                    .ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac
                    .ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }
    }
}
