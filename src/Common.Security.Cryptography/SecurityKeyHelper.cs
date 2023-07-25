using System;
using System.Security.Cryptography;
using System.Linq;
using Common.Security.Cryptography.Exceptions;
using Common.Security.Cryptography.Keys;

namespace Common.Security.Cryptography
{
    public static class SecurityKeyHelper
    {
        public static void ValidateKeySize(int keySize, KeySizes[] keySizes)
        {
            if (keySizes.All(keySizeLimit => keySize < keySizeLimit.MinSize || keySize > keySizeLimit.MaxSize ||
                  keySize % keySizeLimit.SkipSize != 0))
            {
                var messages = string.Join("\n", keySizes.Select(keySizeLimit => $"{keySizeLimit.MinSize} to {keySizeLimit.MaxSize} and be divisible by {keySizeLimit.SkipSize}"));
                throw new KeySizeException($"The provided key, {keySize}, was not valid. The keep must fit in any of the following key sizes:\n{messages}");
            }

            return;
        }

        internal static bool TryGetSecurityKeyGeneratorBaseTypes(Type toCheck, out Type[] implementingTypes)
        {
            var generic = typeof(SecurityKeyGenerator<,,>);
            while (toCheck != null && toCheck != typeof(object))
            {
                var cur = toCheck.IsGenericType ? toCheck.GetGenericTypeDefinition() : toCheck;
                if (generic == cur)
                {
                    implementingTypes = toCheck.GetGenericArguments();
                    return true;
                }
                toCheck = toCheck.BaseType;
            }

            implementingTypes = null;
            return false;
        }
    }
}
