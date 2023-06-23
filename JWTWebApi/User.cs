namespace JWTWebApi
{
    public class User
    {
        public string UserName { get; set; } = string.Empty;
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
        public string RefreshToken { get; set; } = string.Empty;
        public DateTime TokenCreatedAt { get; set; }
        public DateTime TokenExpiration { get; set; }

    }
}
