using Common.Security.Cryptography.Model;
using Common.Security.Cryptography.Ports;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Common.Security.Cryptography.Internal.Services
{
    internal class SecurityKeyProvider : ISecurityKeyProvider
    {
        #region Variables

        private readonly IEnumerable<SecurityKeyDescriptor> _securityKeyDescriptors;
        private readonly IServiceProvider _serviceProvider;

        #endregion

        #region Constructors

        public SecurityKeyProvider(IEnumerable<SecurityKeyDescriptor> securityKeyDescriptors, IServiceProvider serviceProvider)
        {
            _securityKeyDescriptors = securityKeyDescriptors ?? throw new ArgumentNullException(nameof(securityKeyDescriptors));
            _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(securityKeyDescriptors));
        }

        #endregion

        #region ISecurityKeyProvider

        public ISecurityKey GetFrom(SecurityKeyInformation keyInformation)
        {
            if (keyInformation == null)
            {
                throw new ArgumentNullException(nameof(keyInformation));
            }

            var keyInformationType = keyInformation.GetType();
            var descriptor = _securityKeyDescriptors.FirstOrDefault(generator => generator.KeyInformationType == keyInformationType);
            if (descriptor == null)
            {
                throw new InvalidOperationException($"There is no key generator available for key information of type {keyInformationType.FullName}.");
            }

            var keyGenerator = (ISecurityKeyGenerator)_serviceProvider.GetRequiredService(descriptor.GeneratorType);
            return keyGenerator.GenerateKey(keyInformation);
        }

        public ISecurityKey GetFrom(byte[] key, SecurityKeyExchangeInformation exchangeInformation)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }
            if (exchangeInformation == null)
            {
                throw new ArgumentNullException(nameof(exchangeInformation));
            }

            var keyExchangeInformationType = exchangeInformation.GetType();
            var descriptor = _securityKeyDescriptors.FirstOrDefault(generator => generator.KeyExchangeInformationType == keyExchangeInformationType);
            if (descriptor == null)
            {
                throw new InvalidOperationException($"There is no key generator available for key exchange information of type {keyExchangeInformationType.FullName}.");
            }

            var keyGenerator = (ISecurityKeyGenerator)_serviceProvider.GetRequiredService(descriptor.GeneratorType);
            return keyGenerator.GenerateKey(key, exchangeInformation);
        }

        public ISecurityKey GetNew(int keySize, SecurityKeyGenerationParameters parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            var generationParametersType = parameters.GetType();
            var descriptor = _securityKeyDescriptors.FirstOrDefault(generator => generator.KeyGenerationParametersType == generationParametersType);
            if (descriptor == null)
            {
                throw new InvalidOperationException($"There is no key generator available for key generation parameters of type {generationParametersType.FullName}.");
            }

            var keyGenerator = (ISecurityKeyGenerator)_serviceProvider.GetRequiredService(descriptor.GeneratorType);
            return keyGenerator.GenerateKey(keySize, parameters);
        }

        #endregion
    }
}
