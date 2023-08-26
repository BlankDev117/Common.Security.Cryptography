using Common.Security.Cryptography.Keys.Rsa.Internal.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Common.Security.Cryptography.Keys.Rsa
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddRsa(this IServiceCollection services)
        {
            services.AddSecurityKeyDescriptor<RsaKeyGenerator>();

            return services;
        }
    }
}
