using Common.Security.Cryptography.Keys;
using Common.Security.Cryptography.Model;
using Common.Security.Cryptography.Ports;
using Common.Security.Cryptography.SecurityKeys.Rsa.Models;
using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Common.Security.Cryptography.SecurityKeys.Rsa.Internal.Services
{
    internal class RsaSecurityKey : SecurityKey<RsaKeyInformation>
    {
        #region Constructors

        public RsaSecurityKey(RsaKeyInformation rsaKeyInformation)
            : base(rsaKeyInformation)
        {
        }

        #endregion

        #region ISecurityKey

        public override Task<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            using var rsa = new RSACryptoServiceProvider(new CspParameters()
            {
                Flags = CspProviderFlags.UseMachineKeyStore
            })
            {
                PersistKeyInCsp = false
            };
            rsa.ImportCspBlob(SecurityKeyInformation.PublicKey);

            var encryptedBytes = rsa.Encrypt(data, SecurityKeyInformation.EncryptionPadding);
            rsa.Clear();
            return Task.FromResult(encryptedBytes);
        }

        public override Task<byte[]> DecryptAsync(byte[] data, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            using var rsa = new RSACryptoServiceProvider(new CspParameters()
            {
                Flags = CspProviderFlags.UseMachineKeyStore
            })
            {
                PersistKeyInCsp = false
            };
            rsa.ImportCspBlob(SecurityKeyInformation.PrivateKey);

            var encryptedBytes = rsa.Decrypt(data, SecurityKeyInformation.EncryptionPadding);
            rsa.Clear();
            return Task.FromResult(encryptedBytes);
        }

        public override void Dispose()
        {
            if (SecurityKeyInformation == null)
            {
                throw new ObjectDisposedException(nameof(RsaSecurityKey));
            }

            Array.Clear(SecurityKeyInformation.PublicKey, 0, SecurityKeyInformation.PublicKey.Length);
            Array.Clear(SecurityKeyInformation.PrivateKey, 0, SecurityKeyInformation.PrivateKey.Length);
            SecurityKeyInformation = null;
        }

        #endregion
    }
}
