using Common.Security.Cryptography.Keys.Aes.Internal.Services;
using Common.Security.Cryptography.Keys.Rsa.Internal.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Common.Security.Cryptography.Keys
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddSecurityKeys(this IServiceCollection services)
        {
            services.AddSecurityKeyDescriptor<AesKeyGenerator>();
            services.AddSecurityKeyDescriptor<RsaKeyGenerator>();

            return services;
        }
    }
}
