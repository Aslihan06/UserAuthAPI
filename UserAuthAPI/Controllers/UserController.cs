using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;
using UserAuthAPI.Data;
using UserAuthAPI.Models;
using Microsoft.AspNetCore.Identity.Data;

[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    private readonly AppDbContext _context;

    public UserController(AppDbContext context)
    {
        _context = context;
    }

    [HttpPost("Register")]
    public IActionResult Register([FromBody] User user)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        user.Password = HashPassword(user.Password);
        _context.Users.Add(user);
        _context.SaveChanges();

        return Ok("Kullanıcı başarıyla oluşturuldu.");
    }

    private string HashPassword(string password)
    {
        byte[] salt = new byte[16];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }

        string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: password,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 10000,
            numBytesRequested: 32));

        return $"{Convert.ToBase64String(salt)}.{hashed}";
    }
    [HttpPost("Login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = _context.Users.SingleOrDefault(u => u.Email == request.Email);
        if (user == null)
            return Unauthorized("Kullanıcı bulunamadı.");

        if (!VerifyPassword(request.Password, user.Password))
            return Unauthorized("Şifre hatalı.");

        return Ok("Giriş başarılı.");
    }

    private bool VerifyPassword(string password, string storedPassword)
    {
        var parts = storedPassword.Split('.');
        var salt = Convert.FromBase64String(parts[0]);
        var hash = parts[1];

        var computedHash = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: password,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 10000,
            numBytesRequested: 32));

        return hash == computedHash;
    }
}

}

