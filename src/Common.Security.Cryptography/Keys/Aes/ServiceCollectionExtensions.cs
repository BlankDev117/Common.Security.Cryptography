using Common.Security.Cryptography.Keys.Aes.Internal.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Common.Security.Cryptography.Keys.Aes
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddAes(this IServiceCollection services)
        {
            services.AddSecurityKeyDescriptor<AesKeyGenerator>();

            return services;
        }
    }
}
