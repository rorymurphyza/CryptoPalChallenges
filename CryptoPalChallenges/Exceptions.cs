using System;

namespace CryptoPalChallenges
{
    /// <summary>
    /// Thrown when the PCKS#7 padding is not valid. Message should indicate why it is invalid.
    /// </summary>
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