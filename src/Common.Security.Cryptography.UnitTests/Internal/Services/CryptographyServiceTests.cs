using Common.Security.Cryptography.Exceptions;
using Common.Security.Cryptography.Internal.Services;
using Common.Security.Cryptography.Model;
using Common.Security.Cryptography.Ports;
using Common.Security.Cryptography.UnitTests.TestData;
using Moq;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Common.Security.Cryptography.UnitTests.Internal.Services
{
    public class CryptographyServiceTests
    {
        #region Variables

        private readonly Mock<ISecurityKeyProvider> _mockSecurityKeyProvider;

        private readonly CryptographyService _cryptographyService;

        #endregion

        #region Constructors

        public CryptographyServiceTests()
        {
            _mockSecurityKeyProvider = new Mock<ISecurityKeyProvider>();

            _cryptographyService = new CryptographyService(_mockSecurityKeyProvider.Object);
        }

        #endregion

        #region CreateKey (int, KeyGenerationParameters)

        [Fact]
        public void Create_KeyGenerationParameters_ReturnsSecurityKey()
        {
            // Arrange
            var mockKey = new Mock<ISecurityKey>();
            _mockSecurityKeyProvider.Setup(m => m.GetNew(It.IsAny<int>(), It.IsAny<SecurityKeyGenerationParameters>()))
                .Returns(mockKey.Object);

            // Act
            var key = _cryptographyService.CreateKey(1, new TestGenerationParameters());

            // Assert
            Assert.Equal(mockKey.Object, key);
        }

        #endregion

        #region CreateKey (byte[], SecurityKeyExchangeInformation)

        [Fact]
        public void Create_KeyExchangeInformation_ReturnsSecurityKey()
        {
            // Arrange
            var mockKey = new Mock<ISecurityKey>();
            _mockSecurityKeyProvider.Setup(m => m.GetFrom(It.IsAny<byte[]>(), It.IsAny<SecurityKeyExchangeInformation>()))
                .Returns(mockKey.Object);

            // Act
            var key = _cryptographyService.CreateKey(new byte[0], new TestKeyExchangeInformation());

            // Assert
            Assert.Equal(mockKey.Object, key);
        }

        #endregion

        #region CreateKey (KeyInformation)

        [Fact]
        public void Create_KeyInformation_ReturnsSecurityKey()
        {
            // Arrange
            var mockKey = new Mock<ISecurityKey>();
            _mockSecurityKeyProvider.Setup(m => m.GetFrom(It.IsAny<SecurityKeyInformation>()))
                .Returns(mockKey.Object);

            // Act
            var key = _cryptographyService.CreateKey(new TestKeyInformation());

            // Assert
            Assert.Equal(mockKey.Object, key);
        }

        #endregion

        #region SignAndEncryptMessageAsync

        [Fact]
        public async Task SignAndEncryptMessageAsync_NullData_ThrowsArgumentNullException()
        {
            // Arrange/Act/Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => _cryptographyService.SignAndEncryptMessageAsync(null, new Mock<ISecurityKey>().Object, HashAlgorithmName.MD5));
        }

        [Fact]
        public async Task SignAndEncryptMessageAsync_NullSecurityKey_ThrowsArgumentNullException()
        {
            // Arrange/Act/Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => _cryptographyService.SignAndEncryptMessageAsync(new byte[0], null, HashAlgorithmName.MD5));
        }

        [Fact]
        public async Task SignAndEncryptMessageAsync_Valid_ReturnsSuccessfully()
        {
            // Arrange
            var expectedData = new byte[]
            {
                0, 1, 0, 1, 1, 1, 0
            };
            var expectedSignature = new byte[]
            {
                1, 1, 0, 0, 1, 0, 1
            };

            var mockSecurityKey = new Mock<ISecurityKey>();
            mockSecurityKey.Setup(m => m.EncryptAsync(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(expectedData);
            mockSecurityKey.Setup(m => m.SignAsync(It.IsAny<byte[]>(), It.IsAny<HashAlgorithmName>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(expectedSignature);

            // Act
            var result = await _cryptographyService.SignAndEncryptMessageAsync(new byte[0], mockSecurityKey.Object, HashAlgorithmName.SHA256);

            // Assert
            Assert.True(expectedData.SequenceEqual(result.EncryptedData));
            Assert.True(expectedSignature.SequenceEqual(result.Signature));
        }

        #endregion

        #region ValidateAndDecryptMessageAsync

        [Fact]
        public async Task ValidateAndDecryptMessageAsync_NullData_ThrowsArgumentNullException()
        {
            // Arrange/Act/Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => _cryptographyService.ValidateAndDecryptMessageAsync(null, new Mock<ISecurityKey>().Object, HashAlgorithmName.MD5));
        }

        [Fact]
        public async Task ValidateAndDecryptMessageAsync_NullSecurityKey_ThrowsArgumentNullException()
        {
            // Arrange/Act/Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => _cryptographyService.ValidateAndDecryptMessageAsync(new SignedMessage(), null, HashAlgorithmName.MD5));
        }

        [Fact]
        public async Task ValidateAndDecryptMessageAsync_InvalidSignature_ThrowsSignedMessageValidationException()
        {
            // Arrange
            var mockSecurityKey = new Mock<ISecurityKey>();
            mockSecurityKey.Setup(m => m.ValidateSignatureAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>(),
                It.IsAny<HashAlgorithmName>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);

            // Act/Assert
            await Assert.ThrowsAsync<SignedMessageValidationException>(() => _cryptographyService.ValidateAndDecryptMessageAsync(new SignedMessage(), mockSecurityKey.Object,HashAlgorithmName.MD5));
        }

        [Fact]
        public async Task ValidateAndDecryptMessageAsync_ValidSignature_ReturnsSuccessfully()
        {
            // Arrange
            var expectedData = new byte[]
            {
                0, 1, 1, 0, 0, 1, 0
            };

            var mockSecurityKey = new Mock<ISecurityKey>();
            mockSecurityKey.Setup(m => m.ValidateSignatureAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>(),
                It.IsAny<HashAlgorithmName>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);
            mockSecurityKey.Setup(m => m.DecryptAsync(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(expectedData);

            // Act
            var result = await _cryptographyService.ValidateAndDecryptMessageAsync(new SignedMessage(), mockSecurityKey.Object,
                HashAlgorithmName.MD5);

            // Result

        }


        #endregion
    }
}
