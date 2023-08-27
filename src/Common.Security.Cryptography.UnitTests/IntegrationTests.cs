using Common.Security.Cryptography.Keys.Rsa.Models;
using Common.Security.Cryptography.Ports;
using Microsoft.Extensions.DependencyInjection;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Common.Security.Cryptography.UnitTests
{
    public class IntegrationTests
    {
        #region End to End

        [Fact]
        public async Task EndToEnd_SecurityKeyExchange_Testing()
        {
            var serviceCollection = new ServiceCollection();
            serviceCollection.AddCryptography();
            var serviceProvider = serviceCollection.BuildServiceProvider();

            var cryptographyService = serviceProvider.GetRequiredService<ICryptographyService>();
            var personalKey = cryptographyService.CreateKey(512, new RsaKeyGenerationParameters());
            var otherKey = cryptographyService.CreateKey(512, new RsaKeyGenerationParameters());

            var personalExchangeKeyInformation = personalKey.KeyInformation.GetKeyExhangeInformation() as RsaKeyExchangeInformation;
            var otherExchangeKeyInformation =  otherKey.KeyInformation.GetKeyExhangeInformation() as RsaKeyExchangeInformation;

            var personalExchangeKey = cryptographyService.CreateKey(personalKey.KeyInformation.RawKey, otherExchangeKeyInformation);
            var otherExchangeKey = cryptographyService.CreateKey(otherKey.KeyInformation.RawKey, personalExchangeKeyInformation);

            var text = "Hello world, to a new wonderful day!";
            var bytes = Encoding.UTF8.GetBytes(text);
            var message = await cryptographyService.SignAndEncryptMessageAsync(bytes, personalExchangeKey, HashAlgorithmName.SHA1);

            Assert.False(bytes.SequenceEqual(message.EncryptedData));

            var decrypted = await cryptographyService.ValidateAndDecryptMessageAsync(message, otherExchangeKey, HashAlgorithmName.SHA1);
            var decryptedText = Encoding.UTF8.GetString(decrypted);

            Assert.Equal(text, decryptedText);
        }

        #endregion
    }
}
