using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Cryptography;
using System.Text;

namespace Serial_Key_Generator.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private const string EncryptionKey = "MySuperSecretKey123";

        public IndexModel(ILogger<IndexModel> logger)
        {
            _logger = logger;
        }

        [BindProperty]
        public string CompanyName { get; set; }

        [BindProperty]
        public string AppName { get; set; }

        [BindProperty]
        public DateTime CreationDate { get; set; }

        [BindProperty]
        public DateTime ExpirationDate { get; set; }

        [BindProperty]
        public string Key { get; set; }

        [BindProperty]
        public string DecryptedKey { get; set; }

        public void OnGet()
        {
            CreationDate = DateTime.Now;
            ExpirationDate = DateTime.Now;
        }

        public void OnPostGenerate()
        {
            string data = $"{CompanyName}|{AppName}|{CreationDate:yyyyMMdd}|{ExpirationDate:yyyyMMdd}";
            Key = Encrypt(data);
        }

        public void OnPostDecrypt()
        {
            try
            {
                DecryptedKey = Decrypt(Key);

                var parts = DecryptedKey.Split('|');
                if (parts.Length == 4)
                {
                    CompanyName = parts[0];
                    AppName = parts[1];

                    CreationDate = DateTime.ParseExact(parts[2], "yyyyMMdd", null);
                    ExpirationDate = DateTime.ParseExact(parts[3], "yyyyMMdd", null);
                }
                else
                {
                    DecryptedKey = "Invalid key format.";
                }
            }
            catch
            {
                DecryptedKey = "Invalid or corrupted key.";
            }
        }

        private string Encrypt(string plainText)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(EncryptionKey.PadRight(32));
                aes.IV = new byte[16];

                using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    byte[] encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                    return Convert.ToBase64String(encryptedBytes);
                }
            }
        }

        private string Decrypt(string cipherText)
        {
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(EncryptionKey.PadRight(32));
                aes.IV = new byte[16];

                using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    byte[] decryptedBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
        }
    }
}
