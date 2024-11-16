using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace UserAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginRequest
    {
        [Required(ErrorMessage = "Email alanı zorunludur.")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Şifre alanı zorunludur.")]
        public string Password { get; set; } = string.Empty;
    }
}
