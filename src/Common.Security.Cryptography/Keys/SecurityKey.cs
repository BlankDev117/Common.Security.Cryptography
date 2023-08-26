using Common.Security.Cryptography.Model;
using Common.Security.Cryptography.Ports;
using System.Linq;
using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Common.Security.Cryptography.SecurityKeys.Aes.Internal.Services;

namespace Common.Security.Cryptography.Keys
{
    public abstract class SecurityKey<TKeyInformation> : ISecurityKey
        where TKeyInformation: SecurityKeyInformation
    {
        #region Variables

        protected TKeyInformation SecurityKeyInformation;

        #endregion

        #region Constructors

        public SecurityKey(TKeyInformation keyInformation)
        {
            SecurityKeyInformation = keyInformation ?? throw new ArgumentNullException(nameof(keyInformation));
        }

        #endregion

        #region ISecurityKey

        public SecurityKeyInformation KeyInformation => SecurityKeyInformation;

        public abstract Task<byte[]> DecryptAsync(byte[] data, CancellationToken cancellationToken = default);

        public abstract Task<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken = default);

        public abstract void Dispose();

        public Task<byte[]> SignAsync(byte[] data, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            var hashAlgorithm = HashAlgorithm.Create(hashAlgorithmName.Name);
            if (hashAlgorithm == null)
            {
                throw new InvalidOperationException($"The hash algorithm {hashAlgorithmName.Name} is not supported.");
            }

            var dataHash = hashAlgorithm.ComputeHash(data);
            return EncryptAsync(dataHash, cancellationToken);
        }

        public async Task<bool> ValidateSignatureAsync(byte[] data, byte[] signedData, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }
            if (signedData == null)
            {
                throw new ArgumentNullException(nameof(signedData));
            }

            var hashAlgorithm = HashAlgorithm.Create(hashAlgorithmName.Name);
            if (hashAlgorithm == null)
            {
                throw new InvalidOperationException($"The hash algorithm {hashAlgorithmName.Name} is not supported.");
            }

            var decryptedDataHash = await DecryptAsync(signedData, cancellationToken);
            return decryptedDataHash.SequenceEqual(hashAlgorithm.ComputeHash(data));
        }

        #endregion
    }
}