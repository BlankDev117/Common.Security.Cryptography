using Common.Security.Cryptography.Model;
using System.Security.Cryptography;

namespace Common.Security.Cryptography.Keys.Rsa.Models
{
    public class RsaKeyExchangeInformation: SecurityKeyExchangeInformation
    {
        public byte[] PublicKey { get; set; }

        public RSAEncryptionPadding EncryptionPadding { get; set; }

        public RSASignaturePadding SignaturePadding { get; set; }
    }
}
