using Common.Security.Cryptography.Keys.Rsa.Internal.Services;
using Common.Security.Cryptography.Ports;

namespace Common.Security.Cryptography.UnitTests.Keys.Rsa.Internal
{
    public class RsaSecurityKeyTests : SecurityKeyBaseTests
    {
        #region SecurityKeyBaseTests Overrides

        protected override ISecurityKey GetSecurityKey()
            => RsaKeyGenerator.GenerateKey(128);

        #endregion
    }
}
