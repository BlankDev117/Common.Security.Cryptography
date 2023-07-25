using Common.Security.Cryptography.Internal.Services;
using Common.Security.Cryptography.Keys;
using Common.Security.Cryptography.Model;
using Common.Security.Cryptography.Ports;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System;

namespace Common.Security.Cryptography
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddCryptography(this IServiceCollection services)
        {
            services.TryAddTransient<ICryptographyService, CryptographyService>();
            services.TryAddTransient<ISecurityKeyProvider, SecurityKeyProvider>();

            services.AddSecurityKeys();

            return services;
        }

        public static IServiceCollection AddSecurityKeyDescriptor<T>(this IServiceCollection services)
            where T : ISecurityKeyGenerator
        {
            var generatorType = typeof(T);
            if (SecurityKeyHelper.TryGetSecurityKeyGeneratorBaseTypes(generatorType, out var typeImplementations))
            {
                services.AddTransient(_ => new SecurityKeyDescriptor(generatorType,
                   typeImplementations[0], typeImplementations[1], typeImplementations[2]));
                services.AddTransient(generatorType);
                return services;
            }

            throw new InvalidOperationException($"Calling {nameof(AddSecurityKeyDescriptor)} requires a generator that implements {typeof(SecurityKeyGenerator<,,>).FullName}.");
        }
    }
}
