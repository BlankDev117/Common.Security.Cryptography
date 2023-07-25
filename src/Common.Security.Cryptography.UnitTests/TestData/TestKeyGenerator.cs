using Common.Security.Cryptography.Model;
using Common.Security.Cryptography.Ports;

namespace Common.Security.Cryptography.UnitTests.TestData
{
    public class TestKeyGenerator : ISecurityKeyGenerator
    {
        public ISecurityKey TestKey { get; set; }

        public ISecurityKey GenerateKey(int keySize, SecurityKeyGenerationParameters keyGenerationParameters)
        {
            return TestKey;
        }

        public ISecurityKey GenerateKey(byte[] key, SecurityKeyExchangeInformation keyExchangeInformation)
        {
            return TestKey;
        }

        public ISecurityKey GenerateKey(SecurityKeyInformation keyInformation)
        {
            return TestKey;
        }
    }
}
