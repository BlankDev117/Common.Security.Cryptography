using Common.Security.Cryptography.Model;

namespace Common.Security.Cryptography.Ports
{
    public interface ISecurityKeyProvider
    {
        ISecurityKey GetNew(int keySize, SecurityKeyGenerationParameters parameters);

        ISecurityKey GetFrom(SecurityKeyInformation keyInformation);

        ISecurityKey GetFrom(byte[] key, SecurityKeyExchangeInformation exchangeInformation);
    }
}
