namespace JWTWebApi
{
    public class RefreshToken
    {
        public string Token { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public DateTime ExpiresAt { get; set;}
    }
}
