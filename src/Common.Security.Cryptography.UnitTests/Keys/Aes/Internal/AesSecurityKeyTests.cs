using Common.Security.Cryptography.Keys.Aes.Internal.Services;
using Common.Security.Cryptography.Ports;

namespace Common.Security.Cryptography.UnitTests.SecurityKeys.Aes.Internal
{
    public class AesSecurityKeyTests: SecurityKeyBaseTests
    {
        #region SecurityKeyBaseTests Overrides

        protected override ISecurityKey GetSecurityKey()
            => AesKeyGenerator.GenerateKey(128);

        #endregion
    }
}
