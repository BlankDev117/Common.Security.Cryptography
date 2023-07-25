using Common.Security.Cryptography.Model;
using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Common.Security.Cryptography.Ports
{
    public interface ISecurityKey: IDisposable
    {
        SecurityKeyInformation KeyInformation { get; }

        Task<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken = default);

        Task<byte[]> DecryptAsync(byte[] data, CancellationToken cancellationToken = default);

        Task<byte[]> SignAsync(byte[] data, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken = default);

        Task<bool> ValidateSignatureAsync(byte[] data, byte[] signedData, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken = default);
    }
}
