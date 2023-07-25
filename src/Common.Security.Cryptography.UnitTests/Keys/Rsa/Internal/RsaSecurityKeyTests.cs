using Common.Security.Cryptography.Exceptions;
using Common.Security.Cryptography.Keys.Rsa.Internal.Services;
using Common.Security.Cryptography.Keys.Rsa.Models;
using Common.Security.Cryptography.Ports;
using Common.Security.Cryptography.SecurityKeys.Aes.Internal.Services;
using Common.Security.Cryptography.SecurityKeys.Aes.Models;
using Common.Security.Cryptography.SecurityKeys.Rsa.Internal.Services;
using Common.Security.Cryptography.SecurityKeys.Rsa.Models;
using System;
using System.Security.Cryptography;
using Xunit;

namespace Common.Security.Cryptography.UnitTests.SecurityKeys.Rsa.Internal
{
    public class RsaSecurityKeyTests: SecurityKeyBaseTests
    {
        #region SecurityKeyBaseTests Overrides

        protected override ISecurityKey GetSecurityKey()
            => RsaKeyGenerator.GenerateKey(1024);

        #endregion
    }
}
