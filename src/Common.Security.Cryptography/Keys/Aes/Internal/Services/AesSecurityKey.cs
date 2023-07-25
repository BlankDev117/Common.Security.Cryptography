using Common.Security.Cryptography.Model;
using Common.Security.Cryptography.Ports;
using Common.Security.Cryptography.SecurityKeys.Aes.Models;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Common.Security.Cryptography.SecurityKeys.Aes.Internal.Services
{
    internal class AesSecurityKey : ISecurityKey
    {
        #region Variables

        private AesKeyInformation _securityKeyInformation;

        #endregion

        #region Constructors

        public AesSecurityKey(AesKeyInformation aesKeyInformation)
        {
            _securityKeyInformation = aesKeyInformation ?? throw new ArgumentNullException(nameof(aesKeyInformation));
        }

        #endregion

        #region ISecurityKey

        public SecurityKeyInformation KeyInformation => _securityKeyInformation;

        public async Task<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            using var aes = new AesManaged();
            aes.BlockSize = _securityKeyInformation.BlockSize;
            aes.Padding = _securityKeyInformation.PaddingMode;
            aes.Key = _securityKeyInformation.Key;
            aes.IV = _securityKeyInformation.IV;
            aes.Mode = _securityKeyInformation.CipherMode;

            using var dataStream = new MemoryStream(data);
            var encryptedDataStream = new MemoryStream();
            var cryptoStream = new CryptoStream(encryptedDataStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
            await dataStream.CopyToAsync(cryptoStream, cancellationToken);
            cryptoStream.FlushFinalBlock();
            return encryptedDataStream.ToArray();
        }

        public async Task<byte[]> DecryptAsync(byte[] data, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            using var aes = new AesManaged();
            aes.BlockSize = _securityKeyInformation.BlockSize;
            aes.Padding = _securityKeyInformation.PaddingMode;
            aes.Key = _securityKeyInformation.Key;
            aes.IV = _securityKeyInformation.IV;
            aes.Mode = _securityKeyInformation.CipherMode;

            using var encryptedDataStream = new MemoryStream(data);
            using var cryptoStream = new CryptoStream(encryptedDataStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using var decryptedStream = new MemoryStream();
            await cryptoStream.CopyToAsync(decryptedStream, cancellationToken);
            return decryptedStream.ToArray();
        }

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

        public void Dispose()
        {
            if (_securityKeyInformation == null)
            {
                throw new ObjectDisposedException(nameof(AesSecurityKey));
            }

            Array.Clear(_securityKeyInformation.Key, 0, _securityKeyInformation.Key.Length);
            _securityKeyInformation = null;
        }

        #endregion
    }
}
