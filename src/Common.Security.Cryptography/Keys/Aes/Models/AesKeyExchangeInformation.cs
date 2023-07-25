using Common.Security.Cryptography.Model;
using System.Security.Cryptography;

namespace Common.Security.Cryptography.Keys.Aes.Models
{
    public class AesKeyExchangeInformation: SecurityKeyExchangeInformation
    {
        public byte[] IV { get; set; }

        public int BlockSize { get; set; }

        public PaddingMode PaddingMode { get; set; }

        public CipherMode CipherMode { get; set; }
    }
}
