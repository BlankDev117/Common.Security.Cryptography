using Common.Security.Cryptography.Internal.Services;
using Common.Security.Cryptography.Model;
using Common.Security.Cryptography.Ports;
using Common.Security.Cryptography.UnitTests.TestData;
using Moq;
using System;
using System.Collections.Generic;
using Xunit;

namespace Common.Security.Cryptography.UnitTests.Internal.Services
{
    public class SecurityKeyProviderTests
    {
        #region Variables

        private readonly List<SecurityKeyDescriptor> _descriptors;
        private readonly Mock<IServiceProvider> _mockServiceProvider;

        private readonly ISecurityKeyProvider _provider;

        #endregion

        #region Constructors

        public SecurityKeyProviderTests()
        {
            _mockServiceProvider = new Mock<IServiceProvider>();
            _descriptors = new List<SecurityKeyDescriptor>();

            _provider = new SecurityKeyProvider(_descriptors, _mockServiceProvider.Object);
        }

        #endregion

        #region GetFrom (SecurityKeyInformation)

        [Fact]
        public void GetFrom_SecurityKeyInformation_NullKeyInformation_ThrowsArgumentNullException()
        {
            // Arrange/Act/Assert
            Assert.Throws<ArgumentNullException>(() => _provider.GetFrom(null));
        }

        [Fact]
        public void GetFrom_SecurityKeyInformation_NoDescriptorMatchingType_ThrowsInvalidOperationException()
        {
            // Arrange/Act/Assert
            Assert.Throws<InvalidOperationException>(() => _provider.GetFrom(new TestKeyInformation()));
        }

        [Fact]
        public void GetFrom_SecurityKeyInformation_Valid_ReturnsKey()
        {
            // Arrange
            _descriptors.Add(new SecurityKeyDescriptor(typeof(TestKeyGenerator), typeof(TestGenerationParameters),
                typeof(TestKeyInformation), typeof(TestKeyExchangeInformation)));

            var mockSecurityKey = new Mock<ISecurityKey>();
            var generator = new TestKeyGenerator();
            generator.TestKey = mockSecurityKey.Object;

            _mockServiceProvider.Setup(m => m.GetService(It.IsAny<Type>()))
                .Returns(generator);

            // Act
            var key = _provider.GetFrom(new TestKeyInformation());

            // Assert
            Assert.Equal(mockSecurityKey.Object, key);
        }

        #endregion

        #region GetFrom (SecurityKeyExhangeInformation)

        [Fact]
        public void GetFrom_SecurityKeyExhangeInformation_NullKeyInformation_ThrowsArgumentNullException()
        {
            // Arrange/Act/Assert
            Assert.Throws<ArgumentNullException>(() => _provider.GetFrom(null, new TestKeyExchangeInformation()));
        }

        [Fact]
        public void GetFrom_SecurityKeyExhangeInformation_NullExchangeInformation_ThrowsArgumentNullException()
        {
            // Arrange/Act/Assert
            Assert.Throws<ArgumentNullException>(() => _provider.GetFrom(new byte[0], null));
        }

        [Fact]
        public void GetFrom_SecurityKeyExhangeInformation_NoDescriptorMatchingType_ThrowsInvalidOperationException()
        {
            // Arrange/Act/Assert
            Assert.Throws<InvalidOperationException>(() => _provider.GetFrom(new byte[0], new TestKeyExchangeInformation()));
        }

        [Fact]
        public void GetFrom_SecurityKeyExhangeInformation_Valid_ReturnsKey()
        {
            // Arrange
            _descriptors.Add(new SecurityKeyDescriptor(typeof(TestKeyGenerator), typeof(TestGenerationParameters),
                typeof(TestKeyInformation), typeof(TestKeyExchangeInformation)));

            var mockSecurityKey = new Mock<ISecurityKey>();
            var generator = new TestKeyGenerator();
            generator.TestKey = mockSecurityKey.Object;

            _mockServiceProvider.Setup(m => m.GetService(It.IsAny<Type>()))
                .Returns(generator);

            // Act
            var key = _provider.GetFrom(new byte[0], new TestKeyExchangeInformation());

            // Assert
            Assert.Equal(mockSecurityKey.Object, key);
        }

        #endregion

        #region GetNew

        [Fact]
        public void GetNew_NullKeyGenerationParameters_ThrowsArgumentNullException()
        {
            // Arrange/Act/Assert
            Assert.Throws<ArgumentNullException>(() => _provider.GetNew(1, null));
        }

        [Fact]
        public void GetNew_NoDescriptorMatchingType_ThrowsInvalidOperationException()
        {
            // Arrange/Act/Assert
            Assert.Throws<InvalidOperationException>(() => _provider.GetNew(1, new TestGenerationParameters()));
        }

        [Fact]
        public void GetNew_Valid_ReturnsKey()
        {
            // Arrange
            _descriptors.Add(new SecurityKeyDescriptor(typeof(TestKeyGenerator), typeof(TestGenerationParameters),
                typeof(TestKeyInformation), typeof(TestKeyExchangeInformation)));

            var mockSecurityKey = new Mock<ISecurityKey>();
            var generator = new TestKeyGenerator();
            generator.TestKey = mockSecurityKey.Object;

            _mockServiceProvider.Setup(m => m.GetService(It.IsAny<Type>()))
                .Returns(generator);

            // Act
            var key = _provider.GetNew(1, new TestGenerationParameters());

            // Assert
            Assert.Equal(mockSecurityKey.Object, key);
        }

        #endregion
    }
}
