using Common.Security.Cryptography.Keys.Aes;
using Common.Security.Cryptography.Keys.Rsa;
using Microsoft.Extensions.DependencyInjection;

namespace Common.Security.Cryptography.Keys
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddSecurityKeys(this IServiceCollection services)
        {
            services.AddAes();
            services.AddRsa();

            return services;
        }
    }
}
