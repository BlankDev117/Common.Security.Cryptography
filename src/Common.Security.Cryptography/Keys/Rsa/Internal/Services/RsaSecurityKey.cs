using Common.Security.Cryptography.Keys.Rsa.Models;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Common.Security.Cryptography.Keys.Rsa.Internal.Services
{
    internal class RsaSecurityKey : SecurityKey<RsaKeyInformation>
    {
        #region Constructors

        public RsaSecurityKey(RsaKeyInformation rsaKeyInformation)
            : base(rsaKeyInformation)
        {
        }

        #endregion

        #region ISecurityKey

        public override Task<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            var cipher = GetCipher(SecurityKeyInformation.EncryptionPadding);
            cipher.Init(true, SecurityKeyInformation.PublicKey);
            return Task.FromResult(cipher.ProcessBlock(data, 0, data.Length));
        }

        public override Task<byte[]> DecryptAsync(byte[] data, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            var cipher = GetCipher(SecurityKeyInformation.EncryptionPadding);
            cipher.Init(false, SecurityKeyInformation.PrivateKey);
            return Task.FromResult(cipher.ProcessBlock(data, 0, data.Length));
        }

        public override Task<byte[]> SignAsync(byte[] data, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            var signer = GetSigner(SecurityKeyInformation.SignaturePadding, hashAlgorithmName);
            signer.Init(true, SecurityKeyInformation.PrivateKey);
            signer.BlockUpdate(data, 0, data.Length);
            return Task.FromResult(signer.GenerateSignature());
        }

        public override Task<bool> ValidateSignatureAsync(byte[] data, byte[] signedData, HashAlgorithmName hashAlgorithmName, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }
            if (signedData == null)
            {
                throw new ArgumentNullException(nameof(signedData));
            }

            var signer = GetSigner(SecurityKeyInformation.SignaturePadding, hashAlgorithmName);
            signer.Init(false, SecurityKeyInformation.PublicKey);
            signer.BlockUpdate(data, 0, data.Length);
            return Task.FromResult(signer.VerifySignature(signedData));
        }

        public override void Dispose()
        {
            if (SecurityKeyInformation == null)
            {
                throw new ObjectDisposedException(nameof(RsaSecurityKey));
            }

            SecurityKeyInformation = null;
        }

        #endregion

        #region Helpers

        private ISigner GetSigner(RSASignaturePadding signaturePadding, HashAlgorithmName hashAlgorithmName) => signaturePadding.Mode switch
        {
            RSASignaturePaddingMode.Pss => new PssSigner(new RsaBlindedEngine(), DigestUtilities.GetDigest(hashAlgorithmName.Name)),
            RSASignaturePaddingMode.Pkcs1 => new RsaDigestSigner(DigestUtilities.GetDigest(hashAlgorithmName.Name)),
            _ => throw new NotSupportedException($"Signature Padding mode {signaturePadding} is not currently supported for RSA security key.")
        };

        private IAsymmetricBlockCipher GetCipher(RSAEncryptionPadding padding) => padding.Mode switch
        {
            RSAEncryptionPaddingMode.Pkcs1 => new Pkcs1Encoding(new RsaEngine()),
            RSAEncryptionPaddingMode.Oaep => new OaepEncoding(new RsaEngine(), DigestUtilities.GetDigest(padding.OaepHashAlgorithm.Name)),
            _ => throw new NotSupportedException($"Encryption Padding mode {padding} is not currently supported for RSA security key.")
        };

        #endregion
    }
}
