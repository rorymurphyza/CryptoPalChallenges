using System;

namespace CryptoPalChallenges
{
    public class InvalidPaddingException : Exception
    {
        public InvalidPaddingException()
        {

        }
        public InvalidPaddingException(string message) : base(message)
        {

        }
    }
}