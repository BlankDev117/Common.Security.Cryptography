using Common.Security.Cryptography.Ports;
using System;

namespace Common.Security.Cryptography.Model
{
    public class SecurityKeyDescriptor
    {
        #region Variables

        public Type GeneratorType { get; }

        public Type KeyInformationType { get; }

        public Type KeyExchangeInformationType { get; }

        public Type KeyGenerationParametersType { get; }

        #endregion

        #region Constructors

        public SecurityKeyDescriptor(Type generatorType, Type keyGenerationParametersType, Type keyInformationType,
            Type keyExchangeInformationType)
        {
            GeneratorType = ValidateType(nameof(generatorType), generatorType, typeof(ISecurityKeyGenerator));
            KeyGenerationParametersType = ValidateType(nameof(keyGenerationParametersType), keyGenerationParametersType, typeof(SecurityKeyGenerationParameters));
            KeyInformationType = ValidateType(nameof(keyInformationType), keyInformationType, typeof(SecurityKeyInformation));
            KeyExchangeInformationType = ValidateType(nameof(keyExchangeInformationType), keyExchangeInformationType, typeof(SecurityKeyExchangeInformation));
        }

        #endregion

        #region Helpers

        private Type ValidateType(string argName, Type type, Type expectedBaseType)
        {
            if (type == null)
            {
                throw new ArgumentNullException(argName);
            }
            if (expectedBaseType.IsAssignableFrom(type))
            {
                return type;
            }

            throw new InvalidCastException($"The provided type, {type.FullName}, does not inherit from the expected base type, {expectedBaseType}.");
        }

        #endregion
    }
}
