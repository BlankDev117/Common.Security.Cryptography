using Common.Security.Cryptography.Keys.Rsa.Models;
using Common.Security.Cryptography.Model;
using System;
using System.Security.Cryptography;

namespace Common.Security.Cryptography.SecurityKeys.Rsa.Models
{
    public class RsaKeyInformation: SecurityKeyInformation
    {
        #region Variables

        public byte[] PublicKey { get; }

        public byte[] PrivateKey { get; }

        public RSAEncryptionPadding EncryptionPadding { get; }

        public RSASignaturePadding SignaturePadding { get; }

        #endregion

        #region Constructors

        public RsaKeyInformation(byte[] publicKey, byte[] privateKey, RSAEncryptionPadding encryptionPadding,
            RSASignaturePadding signaturePadding)
            : base(SecurityKeyUsageType.Personal)
        {
            PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            PrivateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
            EncryptionPadding = encryptionPadding ?? throw new ArgumentNullException(nameof(encryptionPadding));
            SignaturePadding = signaturePadding ?? throw new ArgumentNullException(nameof(signaturePadding));
        }

        #endregion

        #region SecurityKeyInformation Overrides

        public override byte[] RawKey => PrivateKey;

        public override SecurityKeyExchangeInformation GetKeyExhangeInformation()
        {
            return new RsaKeyExchangeInformation()
            {
                EncryptionPadding = EncryptionPadding,
                SignaturePadding = SignaturePadding,
                PublicKey = PublicKey
            };
        }

        #endregion
    }
}
