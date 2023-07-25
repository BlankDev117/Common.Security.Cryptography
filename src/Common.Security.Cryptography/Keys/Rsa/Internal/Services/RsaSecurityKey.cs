using Common.Security.Cryptography.Model;
using Common.Security.Cryptography.Ports;
using Common.Security.Cryptography.SecurityKeys.Rsa.Models;
using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Common.Security.Cryptography.SecurityKeys.Rsa.Internal.Services
{
    internal class RsaSecurityKey : ISecurityKey
    {
        #region Variables

        private RsaKeyInformation _securityKeyInformation;

        #endregion

        #region Constructors

        public RsaSecurityKey(RsaKeyInformation rsaKeyInformation)
        {
            _securityKeyInformation = rsaKeyInformation ?? throw new ArgumentNullException(nameof(rsaKeyInformation));
        }

        #endregion

        #region ISecurityKey

        public SecurityKeyInformation KeyInformation => _securityKeyInformation;

        public Task<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken = default)
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
            rsa.ImportCspBlob(_securityKeyInformation.PublicKey);

            var encryptedBytes = rsa.Encrypt(data, _securityKeyInformation.EncryptionPadding);
            rsa.Clear();
            return Task.FromResult(encryptedBytes);
        }

        public Task<byte[]> DecryptAsync(byte[] data, CancellationToken cancellationToken = default)
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
            rsa.ImportCspBlob(_securityKeyInformation.PrivateKey);

            var encryptedBytes = rsa.Decrypt(data, _securityKeyInformation.EncryptionPadding);
            rsa.Clear();
            return Task.FromResult(encryptedBytes);
        }

        public Task<byte[]> SignAsync(byte[] data, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken = default)
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
            rsa.ImportCspBlob(_securityKeyInformation.PrivateKey);

            var signedData = rsa.SignData(data, hashAlgorithmName, _securityKeyInformation.SignaturePadding);
            rsa.Clear();
            return Task.FromResult(signedData);
        }

        public Task<bool> ValidateSignatureAsync(byte[] data, byte[] signedData, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }
            if (signedData == null)
            {
                throw new ArgumentNullException(nameof(signedData));
            }

            using var rsa = new RSACryptoServiceProvider(new CspParameters()
            {
                Flags = CspProviderFlags.UseMachineKeyStore
            })
            {
                PersistKeyInCsp = false
            };
            rsa.ImportCspBlob(_securityKeyInformation.PublicKey);

            var isValid = rsa.VerifyData(data, signedData, hashAlgorithmName, _securityKeyInformation.SignaturePadding);
            rsa.Clear();
            return Task.FromResult(isValid);
        }

        public void Dispose()
        {
            if (_securityKeyInformation == null)
            {
                throw new ObjectDisposedException(nameof(RsaSecurityKey));
            }

            Array.Clear(_securityKeyInformation.PublicKey, 0, _securityKeyInformation.PublicKey.Length);
            Array.Clear(_securityKeyInformation.PrivateKey, 0, _securityKeyInformation.PrivateKey.Length);
            _securityKeyInformation = null;
        }

        #endregion
    }
}
