using Common.Security.Cryptography.Keys.Aes.Models;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Common.Security.Cryptography.Keys.Aes.Internal.Services
{
    internal class AesSecurityKey : SecurityKey<AesKeyInformation>
    {
        #region Constructors

        public AesSecurityKey(AesKeyInformation aesKeyInformation)
            : base(aesKeyInformation)
        {
        }

        #endregion

        #region ISecurityKey

        public override async Task<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            using var aes = new AesManaged();
            aes.BlockSize = SecurityKeyInformation.BlockSize;
            aes.Padding = SecurityKeyInformation.PaddingMode;
            aes.Key = SecurityKeyInformation.Key;
            aes.IV = SecurityKeyInformation.IV;
            aes.Mode = SecurityKeyInformation.CipherMode;

            using var dataStream = new MemoryStream(data);
            var encryptedDataStream = new MemoryStream();
            var cryptoStream = new CryptoStream(encryptedDataStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
            await dataStream.CopyToAsync(cryptoStream, cancellationToken);
            cryptoStream.FlushFinalBlock();
            return encryptedDataStream.ToArray();
        }

        public override async Task<byte[]> DecryptAsync(byte[] data, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            using var aes = new AesManaged();
            aes.BlockSize = SecurityKeyInformation.BlockSize;
            aes.Padding = SecurityKeyInformation.PaddingMode;
            aes.Key = SecurityKeyInformation.Key;
            aes.IV = SecurityKeyInformation.IV;
            aes.Mode = SecurityKeyInformation.CipherMode;

            using var encryptedDataStream = new MemoryStream(data);
            using var cryptoStream = new CryptoStream(encryptedDataStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using var decryptedStream = new MemoryStream();
            await cryptoStream.CopyToAsync(decryptedStream, cancellationToken);
            return decryptedStream.ToArray();
        }

        public override void Dispose()
        {
            if (SecurityKeyInformation == null)
            {
                throw new ObjectDisposedException(nameof(AesSecurityKey));
            }

            Array.Clear(SecurityKeyInformation.Key, 0, SecurityKeyInformation.Key.Length);
            SecurityKeyInformation = null;
        }

        #endregion
    }
}
