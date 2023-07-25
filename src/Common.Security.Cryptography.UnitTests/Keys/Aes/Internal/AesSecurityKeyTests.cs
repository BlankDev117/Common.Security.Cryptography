using Common.Security.Cryptography.Exceptions;
using Common.Security.Cryptography.Keys.Aes.Internal.Services;
using Common.Security.Cryptography.Keys.Aes.Models;
using Common.Security.Cryptography.Keys.Rsa.Internal.Services;
using Common.Security.Cryptography.Ports;
using Common.Security.Cryptography.SecurityKeys.Aes.Internal.Services;
using Common.Security.Cryptography.SecurityKeys.Aes.Models;
using System;
using System.Security.Cryptography;
using Xunit;

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
