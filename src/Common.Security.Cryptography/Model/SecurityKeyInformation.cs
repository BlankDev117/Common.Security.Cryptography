namespace Common.Security.Cryptography.Model
{
    public abstract class SecurityKeyInformation
    {
        public SecurityKeyUsageType KeyUsageType { get; }

        public abstract byte[] RawKey { get; }

        public abstract SecurityKeyExchangeInformation GetKeyExhangeInformation();

        protected SecurityKeyInformation(SecurityKeyUsageType keyUsageType) 
        {
            KeyUsageType = keyUsageType;
        }
    }
}
