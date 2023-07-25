using Common.Security.Cryptography.Model;
using System.Security.Cryptography;

namespace Common.Security.Cryptography.Keys.Aes.Models
{
    public class AesKeyGenerationParameters: SecurityKeyGenerationParameters
    {
        public int BlockSize { get; set; } = 128;

        public PaddingMode PaddingMode { get; set; } = PaddingMode.PKCS7;

        public CipherMode CipherMode { get; set; } = CipherMode.CBC;
    }
}
