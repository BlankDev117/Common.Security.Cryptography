using Common.Security.Cryptography.Keys.Aes.Models;
using Common.Security.Cryptography.Model;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Common.Security.Cryptography.SecurityKeys.Aes.Models
{
    public class AesKeyInformation : SecurityKeyInformation
    {
        #region Variables

        public byte[] Key { get; }

        public byte[] IV { get; }

        public int BlockSize { get; }

        public PaddingMode PaddingMode { get; }

        public CipherMode CipherMode { get; }

        #endregion

        #region Constructors

        public AesKeyInformation(byte[] key, byte[] iv, int blockSize, PaddingMode paddingMode, 
            CipherMode cipherMode)
            : base(SecurityKeyUsageType.Personal)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
            IV = iv ?? throw new ArgumentNullException(nameof(iv));
            BlockSize = blockSize;
            PaddingMode = paddingMode;
            CipherMode = cipherMode;
        }

        public AesKeyInformation(byte[] key, AesKeyExchangeInformation keyExhangeInformation)
            : base(SecurityKeyUsageType.Exchange)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
            if (keyExhangeInformation == null)
            {
                throw new ArgumentNullException(nameof(keyExhangeInformation));
            }
            IV = keyExhangeInformation.IV ?? throw new ArgumentNullException(nameof(keyExhangeInformation.IV));
            BlockSize = keyExhangeInformation.BlockSize;
            PaddingMode = keyExhangeInformation.PaddingMode;
            CipherMode = keyExhangeInformation.CipherMode;
        }

        #endregion

        #region SecurityKeyInformation Overrides

        public override byte[] RawKey => Key;

        public override SecurityKeyExchangeInformation GetKeyExhangeInformation()
        {
            return new AesKeyExchangeInformation()
            {
                BlockSize = BlockSize,
                CipherMode = CipherMode,
                PaddingMode = PaddingMode,
                IV = IV
            };
        }

        #endregion
    }
}
