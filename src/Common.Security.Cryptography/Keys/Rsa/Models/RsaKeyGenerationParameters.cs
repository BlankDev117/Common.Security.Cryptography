using Common.Security.Cryptography.Model;
using System.Security.Cryptography;

namespace Common.Security.Cryptography.Keys.Rsa.Models
{
    public class RsaKeyGenerationParameters: SecurityKeyGenerationParameters
    {
        public RSAEncryptionPadding EncryptionPadding { get; set; } = RSAEncryptionPadding.Pkcs1;

        public RSASignaturePadding SignaturePadding { get; set; } = RSASignaturePadding.Pkcs1;
    }
}
