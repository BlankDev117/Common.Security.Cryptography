﻿using Common.Security.Cryptography.Exceptions;
using Common.Security.Cryptography.Keys.Aes.Internal.Services;
using Common.Security.Cryptography.Keys.Aes.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Common.Security.Cryptography.UnitTests.Keys.Aes.Internal
{
    public class AesKeyGeneratorTests
    {
        #region Variables

        private readonly AesKeyGenerator _generator;

        #endregion

        #region Constructors

        public AesKeyGeneratorTests()
        {
            _generator = new AesKeyGenerator();
        }

        #endregion

        #region GenerateKey (int, KeyInformation)

        [Fact]
        public void Generate_GenerationParameters_NullKeyGenerationParameters_ThrowsArgumentNullException()
        {
            // Arrange/Act/Assert
            Assert.Throws<ArgumentNullException>(() => _generator.GenerateKey(1, null));
        }

        [Theory]
        // Valid Key Sizes: 128 - 256 Steps of 64
        [InlineData(127)]
        [InlineData(257)]
        [InlineData(129)]
        [InlineData(201)]
        public void Generate_GenerationParameters_InvalidKeySize_ThrowsKeySizeException(int keySize)
        {
            // Arrange/Act/Assert
            Assert.Throws<KeySizeException>(() => _generator.GenerateKey(keySize, new AesKeyGenerationParameters()));
        }

        [Fact]
        public void Generate_GenerationParameters_GeneratesNewKey()
        {
            // Arrange/Act
            using var key = _generator.GenerateKey(128, new  AesKeyGenerationParameters());

            // Assert
            Assert.NotNull(key);
        }

        #endregion
    }
}
