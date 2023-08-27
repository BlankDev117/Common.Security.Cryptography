using Common.Security.Cryptography.Keys.Aes.Models;
using Common.Security.Cryptography.Ports;
using System;

namespace Common.Security.Cryptography.Keys.Aes.Internal.Services
{
    internal class AesKeyGenerator : SecurityKeyGenerator<AesKeyGenerationParameters, AesKeyInformation, AesKeyExchangeInformation>
    {
        #region Static

        internal static ISecurityKey GenerateKey(int keySize)
        {
            return new AesKeyGenerator().GenerateKey(keySize, new AesKeyGenerationParameters());
        }

        #endregion

        #region SecurityKeyGenerator Overrides

        protected override ISecurityKey GenerateKey(int keySize, AesKeyGenerationParameters keyGenerationParameters)
        {
            if (keyGenerationParameters == null)
            {
                throw new ArgumentNullException(nameof(keyGenerationParameters));
            }

            using var aes = System.Security.Cryptography.Aes.Create();
            SecurityKeyHelper.ValidateKeySize(keySize, aes.LegalKeySizes);

            aes.GenerateKey();
            aes.GenerateIV();
            return new AesSecurityKey(new AesKeyInformation(aes.Key, aes.IV, keyGenerationParameters.BlockSize,
                keyGenerationParameters.PaddingMode, keyGenerationParameters.CipherMode));
        }

        protected override ISecurityKey GenerateKey(byte[] key, AesKeyExchangeInformation keyExchangeInformation)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }
            if (keyExchangeInformation == null)
            {
                throw new ArgumentNullException(nameof(keyExchangeInformation));
            }
            if (keyExchangeInformation.IV == null)
            {
                throw new ArgumentNullException(nameof(keyExchangeInformation.IV));
            }

            return new AesSecurityKey(new AesKeyInformation(key, keyExchangeInformation.IV, keyExchangeInformation.BlockSize,
                keyExchangeInformation.PaddingMode, keyExchangeInformation.CipherMode));
        }

        protected override ISecurityKey GenerateKey(AesKeyInformation keyInformation)
        {
            return new AesSecurityKey(keyInformation);
        }

        #endregion
    }
}
