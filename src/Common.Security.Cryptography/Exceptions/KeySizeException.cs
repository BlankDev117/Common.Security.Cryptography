using System;

namespace Common.Security.Cryptography.Exceptions
{
    public class KeySizeException: Exception
    {
        public KeySizeException(string message)
            : base(message)
        {
        }
    }
}
