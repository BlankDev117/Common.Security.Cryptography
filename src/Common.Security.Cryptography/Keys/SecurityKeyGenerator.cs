using Common.Security.Cryptography.Model;
using Common.Security.Cryptography.Ports;
using System;

namespace Common.Security.Cryptography.Keys
{
    public abstract class SecurityKeyGenerator<TKeyGenerationParameters, TKeyInformation, TKeyExchangeInformation> : ISecurityKeyGenerator
        where TKeyGenerationParameters : SecurityKeyGenerationParameters
        where TKeyInformation : SecurityKeyInformation
        where TKeyExchangeInformation : SecurityKeyExchangeInformation
    {
        #region ISecurityKeyGenerator

        public ISecurityKey GenerateKey(int keySize, SecurityKeyGenerationParameters keyGenerationParameters)
        {
            if (keyGenerationParameters == null)
            {
                throw new ArgumentNullException(nameof(keyGenerationParameters));
            }

            return keyGenerationParameters is TKeyGenerationParameters typedParameters
                ? GenerateKey(keySize, typedParameters)
                : throw new NotSupportedException($"The provided parameters of type, {keyGenerationParameters.GetType().FullName}, are not supported by this key generator.");
        }

        public ISecurityKey GenerateKey(byte[] key, SecurityKeyExchangeInformation keyExchangeInformation)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }
            if (keyExchangeInformation == null)
            {
                throw new ArgumentNullException(nameof(keyExchangeInformation));
            }
         
            return keyExchangeInformation is TKeyExchangeInformation typedParameters
                ? GenerateKey(key, typedParameters)
                : throw new NotSupportedException($"The provided exchange information of type, {keyExchangeInformation.GetType().FullName}, are not supported by this key generator.");
        }

        public ISecurityKey GenerateKey(SecurityKeyInformation keyInformation)
        {
            if (keyInformation == null)
            {
                throw new ArgumentNullException(nameof(keyInformation));
            }

            return keyInformation is TKeyInformation typedParameters
                ? GenerateKey(typedParameters)
                : throw new NotSupportedException($"The provided key information of type, {keyInformation.GetType().FullName}, are not supported by this key generator.");
        }

        #endregion

        #region Helpers

        protected abstract ISecurityKey GenerateKey(int keySize, TKeyGenerationParameters keyGenerationParameters);

        protected abstract ISecurityKey GenerateKey(byte[] key, TKeyExchangeInformation keyExchangeInformation);

        protected abstract ISecurityKey GenerateKey(TKeyInformation keyInformation);

        #endregion
    }
}
