using System.Numerics;
using System.Threading;
using System.Threading.Tasks;

namespace Common.Security.Cryptography.Keys.Rsa.Ports
{
    public interface IPrimeNumberGenerator
    {
        public Task<BigInteger> NextPrimeAsync(int bitLength, CancellationToken cancellationToken = default);
    }
}
