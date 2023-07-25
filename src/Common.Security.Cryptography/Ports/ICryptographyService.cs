using Common.Security.Cryptography.Model;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Common.Security.Cryptography.Ports
{
    public interface ICryptographyService
    {
        ISecurityKey CreateKey(int keySize, SecurityKeyGenerationParameters parameters);

        ISecurityKey CreateKey(SecurityKeyInformation keyInformation);

        ISecurityKey CreateKey(byte[] key, SecurityKeyExchangeInformation exchangeInformation);

        Task<SignedMessage> SignAndEncryptMessageAsync(byte[] message, ISecurityKey securityKey, HashAlgorithmName hashAlgorithmName, 
            CancellationToken cancellationToken = default);

        Task<byte[]> ValidateAndDecryptMessageAsync(SignedMessage signedMessage, ISecurityKey securityKey, HashAlgorithmName hashAlgorithmName, 
            CancellationToken cancellationToken = default);
    }
}
