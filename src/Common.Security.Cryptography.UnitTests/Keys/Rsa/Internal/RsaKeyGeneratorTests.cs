﻿using Common.Security.Cryptography.Exceptions;
using Common.Security.Cryptography.Keys.Aes.Models;
using Common.Security.Cryptography.Keys.Rsa.Internal.Services;
using Common.Security.Cryptography.Keys.Rsa.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Common.Security.Cryptography.UnitTests.Keys.Rsa.Internal
{
    public class RsaKeyGeneratorTests
    {
        #region Variables

        private readonly RsaKeyGenerator _generator;

        #endregion

        #region Constructors

        public RsaKeyGeneratorTests()
        {
            _generator = new RsaKeyGenerator();
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
        [InlineData(343)]
        [InlineData(425)]
        [InlineData(1111)]
        [InlineData(65000)]
        public void Generate_GenerationParameters_InvalidKeySize_ThrowsKeySizeException(int keySize)
        {
            // Arrange/Act/Assert
            Assert.Throws<KeySizeException>(() => _generator.GenerateKey(keySize, new RsaKeyGenerationParameters()));
        }

        [Fact]
        public void Generate_GenerationParameters_GeneratesNewKey()
        {
            // Arrange/Act
            var keys = new List<long>();
            for (var i = 0; i < 1; i++)
            {
                using var key = _generator.GenerateKey(128, new RsaKeyGenerationParameters());
                keys.Add(BitConverter.ToInt64(key.KeyInformation.RawKey));
            }

            // Assert
            Assert.Equal(keys.Count, keys.Distinct().Count());
        }

        #endregion
    }
}
