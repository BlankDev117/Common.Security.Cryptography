using Common.Security.Cryptography.Exceptions;
using Common.Security.Cryptography.Model;
using Common.Security.Cryptography.Ports;
using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Common.Security.Cryptography.Internal.Services
{
    internal class CryptographyService : ICryptographyService
    {
        #region Variables

        private readonly ISecurityKeyProvider _keyProvider;

        #endregion

        #region Constructors

        public CryptographyService(ISecurityKeyProvider keyProvider)
        {
            _keyProvider = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider));
        }

        #endregion

        #region ICryptographyService

        public ISecurityKey CreateKey(int keySize, SecurityKeyGenerationParameters parameters)
        {
            return _keyProvider.GetNew(keySize, parameters);
        }

        public ISecurityKey CreateKey(SecurityKeyInformation keyInformation)
        {
            return _keyProvider.GetFrom(keyInformation);
        }

        public ISecurityKey CreateKey(byte[] key, SecurityKeyExchangeInformation exchangeInformation)
        {
            return _keyProvider.GetFrom(key, exchangeInformation);
        }

        public async Task<SignedMessage> SignAndEncryptMessageAsync(byte[] message, ISecurityKey securityKey, HashAlgorithmName hashAlgorithmName,
            CancellationToken cancellationToken = default)
        {
            if (message == null)
            {
                throw new ArgumentNullException(nameof(message));
            }
            if (securityKey == null)
            {
                throw new ArgumentNullException(nameof(securityKey));
            }

            var encryptedData = await securityKey.EncryptAsync(message, cancellationToken);
            var signature = await securityKey.SignAsync(encryptedData, hashAlgorithmName, cancellationToken);

            return new SignedMessage
            {
                Signature = signature,
                EncryptedData = encryptedData
            };
        }

        public async Task<byte[]> ValidateAndDecryptMessageAsync(SignedMessage signedMessage, ISecurityKey securityKey, HashAlgorithmName hashAlgorithmName,
            CancellationToken cancellationToken = default)
        {
            if (signedMessage == null)
            {
                throw new ArgumentNullException(nameof(signedMessage));
            }
            if (securityKey == null)
            {
                throw new ArgumentNullException(nameof(securityKey));
            }

            var isMessageAuthentic = await securityKey.ValidateSignatureAsync(signedMessage.EncryptedData, signedMessage.Signature, hashAlgorithmName, cancellationToken);
            if (isMessageAuthentic)
            {
                return await securityKey.DecryptAsync(signedMessage.EncryptedData, cancellationToken);
            }

            throw new SignedMessageValidationException("The signed message could not be validated from the sender and is thus comprimised.");
        }

        #endregion
    }
}
