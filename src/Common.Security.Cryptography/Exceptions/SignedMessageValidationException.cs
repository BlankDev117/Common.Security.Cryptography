using System;

namespace Common.Security.Cryptography.Exceptions
{
    public class SignedMessageValidationException: Exception
    {
        public SignedMessageValidationException(string message) 
            : base(message)
        { 
        }
    }
}
