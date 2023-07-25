using Common.Security.Cryptography.Ports;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Common.Security.Cryptography.UnitTests.SecurityKeys
{
    public abstract class SecurityKeyBaseTests
    {

        #region EncryptAsync

        [Fact]
        public async Task EncryptAsync_NullData_ThrowsArgumentNullException()
        {
            // Arrange
            var key = GetSecurityKey();

            // Act/Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => key.EncryptAsync(null));
        }

        [Fact]
        public async Task EncryptAsync_Valid_EncryptsData()
        {
            // Arrange
            var key = GetSecurityKey();
            var phrase = "A day in the life of a unit test.";
            var data = Encoding.UTF8.GetBytes(phrase);

            // Act
            var encryptedData = await key.EncryptAsync(data);

            // Assert
            Assert.NotEqual(phrase, Encoding.UTF8.GetString(encryptedData));
        }

        #endregion

        #region DecryptAsync

        [Fact]
        public async Task DecryptAsync_NullData_ThrowsArgumentNullException()
        {
            // Arrange
            var key = GetSecurityKey();

            // Act/Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => key.DecryptAsync(null));
        }

        [Fact]
        public async Task DecryptAsync_Valid_DecryptsData()
        {
            // Arrange
            var key = GetSecurityKey();

            var phrase = "A day in the life of a unit test.";
            var data = Encoding.UTF8.GetBytes(phrase);
            var encryptedData = await key.EncryptAsync(data);

            // Act
            var decryptedData = await key.DecryptAsync(encryptedData);

            // Assert
            Assert.Equal(phrase, Encoding.UTF8.GetString(decryptedData));
        }

        #endregion

        #region SignAsync

        [Fact]
        public async Task SignAsync_NullData_ThrowsArgumentNullException()
        {
            // Arrange
            var key = GetSecurityKey();

            // Act/Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => key.SignAsync(null, HashAlgorithmName.SHA256));
        }

        [Fact]
        public async Task SignAsync_Valid_ReturnsSignedData()
        {
            // Arrange
            var key = GetSecurityKey();

            var data = Encoding.UTF8.GetBytes("A day in the life of a unit test.");

            // Act
            var signedData = await key.SignAsync(data, HashAlgorithmName.SHA256);

            // Assert
            Assert.NotEqual(BitConverter.ToInt64(data), BitConverter.ToInt64(signedData));
        }

        #endregion

        #region ValidateSignatureAsync

        [Fact]
        public async Task ValidateSignatureAsync_NullData_ThrowsArgumentNullException()
        {
            // Arrange
            var key = GetSecurityKey();

            // Act/Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => key.ValidateSignatureAsync(null, new byte[0], HashAlgorithmName.SHA256)); ;
        }

        [Fact]
        public async Task ValidateSignatureAsync_NullSignature_ThrowsArgumentNullException()
        {
            // Arrange
            var key = GetSecurityKey();

            // Act/Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => key.ValidateSignatureAsync(new byte[0], null, HashAlgorithmName.SHA256));
        }

        [Fact]
        public async Task ValidateSignatureAsync_InvalidSignature_ReturnsFalse()
        {
            // Arrange
            var key = GetSecurityKey();

            var data = Encoding.UTF8.GetBytes("A day in the life of a unit test.");
            var signedData = await key.SignAsync(data, HashAlgorithmName.SHA512);

            // Act
            var validationResult = await key.ValidateSignatureAsync(data, signedData, HashAlgorithmName.SHA256);

            // Assert
            Assert.False(validationResult);
        }

        [Fact]
        public async Task ValidateSignatureAsync_ValidSignature_ReturnsTrue()
        {
            // Arrange
            var key = GetSecurityKey();

            var data = Encoding.UTF8.GetBytes("A day in the life of a unit test.");
            var signedData = await key.SignAsync(data, HashAlgorithmName.SHA256);

            // Act
            var validationResult = await key.ValidateSignatureAsync(data, signedData, HashAlgorithmName.SHA256);

            // Assert
            Assert.True(validationResult);
        }

        #endregion

        #region Dispose

        [Fact]
        public void Dispose_Valid_ReturnsSuccessfully()
        {
            // Arrange
            var key = GetSecurityKey();

            // Act/Assert
            key.Dispose();
        }

        [Fact]
        public void Dispose_CalledTwice_ThrowsDisposedException()
        {
            // Arrange
            var key = GetSecurityKey();

            // Act
            key.Dispose();

            // Assert
            Assert.Throws<ObjectDisposedException>(() => key.Dispose());
        }

        #endregion

        #region Helpers

        protected abstract ISecurityKey GetSecurityKey();

        #endregion
    }
}
