using Common.Security.Cryptography.Keys.Aes.Internal.Services;
using Common.Security.Cryptography.Ports;

namespace Common.Security.Cryptography.UnitTests.Keys.Aes.Internal
{
    public class AesSecurityKeyTests : SecurityKeyBaseTests
    {
        #region SecurityKeyBaseTests Overrides

        protected override ISecurityKey GetSecurityKey()
            => AesKeyGenerator.GenerateKey(128);

        #endregion
    }
}
