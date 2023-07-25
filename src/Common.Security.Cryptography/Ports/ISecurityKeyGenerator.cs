using Common.Security.Cryptography.Model;

namespace Common.Security.Cryptography.Ports
{
    public interface ISecurityKeyGenerator
    {
        ISecurityKey GenerateKey(int keySize, SecurityKeyGenerationParameters keyGenerationParameters);

        ISecurityKey GenerateKey(byte[] key, SecurityKeyExchangeInformation keyExchangeInformation);

        ISecurityKey GenerateKey(SecurityKeyInformation keyInformation);
    }
}
