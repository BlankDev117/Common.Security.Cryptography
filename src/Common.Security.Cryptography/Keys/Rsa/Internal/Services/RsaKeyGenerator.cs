using Common.Security.Cryptography.Keys.Rsa.Models;
using Common.Security.Cryptography.Ports;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Security.Cryptography;

namespace Common.Security.Cryptography.Keys.Rsa.Internal.Services
{
    internal class RsaKeyGenerator : SecurityKeyGenerator<RsaKeyGenerationParameters, RsaKeyInformation, RsaKeyExchangeInformation>
    {
        #region Static

        internal static ISecurityKey GenerateKey(int keySize)
        {
            return new RsaKeyGenerator().GenerateKey(keySize, new RsaKeyGenerationParameters());
        }

        #endregion

        #region Variables

        private const long DefaultPublicExponent = 65537;
        private const int NumberOfTestsForPrime = 500;
        private static readonly KeySizes ValidKeySizes = new KeySizes(128, 512, 64);

        #endregion

        #region SecurityKeyGenerator Overrides

        protected override ISecurityKey GenerateKey(int keySize, RsaKeyGenerationParameters keyGenerationParameters)
        {
            SecurityKeyHelper.ValidateKeySize(keySize, ValidKeySizes);

            var rsaKeyGenerator = new RsaKeyPairGenerator();
            rsaKeyGenerator.Init(new Org.BouncyCastle.Crypto.Parameters.RsaKeyGenerationParameters(BigInteger.ValueOf(DefaultPublicExponent),
                new SecureRandom(),
                keySize * 8, // BouncyCastle uses bit length
                NumberOfTestsForPrime));

            var key = rsaKeyGenerator.GenerateKeyPair();
            return new RsaSecurityKey(new RsaKeyInformation(key.Public, key.Private, keyGenerationParameters.EncryptionPadding, keyGenerationParameters.SignaturePadding));
        }

        protected override ISecurityKey GenerateKey(byte[] privateKey, RsaKeyExchangeInformation keyExchangeInformation)
        {
            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }
            if (keyExchangeInformation.PublicKey == null)
            {
                throw new ArgumentNullException(nameof(keyExchangeInformation.PublicKey));
            }

            var rsaPublicKey = PublicKeyFactory.CreateKey(keyExchangeInformation.PublicKey);
            var rsaPrivateKey = PrivateKeyFactory.CreateKey(privateKey);
            return new RsaSecurityKey(new RsaKeyInformation(rsaPublicKey, rsaPrivateKey,
                keyExchangeInformation.EncryptionPadding, keyExchangeInformation.SignaturePadding));
        }

        protected override ISecurityKey GenerateKey(RsaKeyInformation keyInformation)
        {
            return new RsaSecurityKey(keyInformation);
        }

        #endregion
    }
}
