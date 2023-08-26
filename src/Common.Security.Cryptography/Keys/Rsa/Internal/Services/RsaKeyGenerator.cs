using Common.Security.Cryptography.Keys.Rsa.Models;
using Common.Security.Cryptography.Ports;
using Common.Security.Cryptography.SecurityKeys.Rsa.Internal.Services;
using Common.Security.Cryptography.SecurityKeys.Rsa.Models;
using System;
using System.Security.Cryptography;

namespace Common.Security.Cryptography.Keys.Rsa.Internal.Services
{
    internal class RsaKeyGenerator : SecurityKeyGenerator<RsaKeyGenerationParameters, RsaKeyInformation, RsaKeyExchangeInformation>
    {
        protected override ISecurityKey GenerateKey(int keySize, RsaKeyGenerationParameters keyGenerationParameters)
        {
            using var rsa = new RSACryptoServiceProvider(new CspParameters()
            {
                Flags = CspProviderFlags.UseMachineKeyStore
            })
            {
                PersistKeyInCsp = false
            };

            try
            {
                SecurityKeyHelper.ValidateKeySize(keySize, rsa.LegalKeySizes);
            }
            catch (Exception)
            {
                rsa.Clear();
                throw;
            }

            var key = new RsaSecurityKey(new RsaKeyInformation(rsa.ExportCspBlob(false), rsa.ExportCspBlob(true),
                keyGenerationParameters.EncryptionPadding, keyGenerationParameters.SignaturePadding));

            rsa.Clear();
            return key;
        }

        protected override ISecurityKey GenerateKey(byte[] privateKey, RsaKeyExchangeInformation keyExchangeInformation)
        {
            if (keyExchangeInformation.PublicKey == null)
            {
                throw new ArgumentNullException(nameof(keyExchangeInformation.PublicKey));
            }

            return new RsaSecurityKey(new RsaKeyInformation(keyExchangeInformation.PublicKey, privateKey,
                keyExchangeInformation.EncryptionPadding, keyExchangeInformation.SignaturePadding));
        }

        protected override ISecurityKey GenerateKey(RsaKeyInformation keyInformation)
        {
            return new RsaSecurityKey(keyInformation);
        }

        internal static ISecurityKey GenerateKey(int keySize)
        {
            return new RsaKeyGenerator().GenerateKey(keySize, new RsaKeyGenerationParameters());
        }
    }
}
