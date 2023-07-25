using Common.Security.Cryptography.Model;
using System;

namespace Common.Security.Cryptography.UnitTests.TestData
{
    public class TestKeyInformation : SecurityKeyInformation
    {
        public TestKeyInformation() 
            : base(SecurityKeyUsageType.Personal)
        {
        }

        public override byte[] RawKey => throw new NotImplementedException();

        public override SecurityKeyExchangeInformation GetKeyExhangeInformation()
        {
            throw new NotImplementedException();
        }
    }
}
