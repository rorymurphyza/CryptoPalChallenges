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

    /// <summary>
    /// Thrown when BlockCipher key size is not the same as the given BlockSize. Message should indicate why they don't match.
    /// </summary>
    public class IncorrectKeySizeException : Exception
    {
        public IncorrectKeySizeException()
        {

        }
        public IncorrectKeySizeException(string message) : base(message)
        {

        }
    }

    /// <summary>
    /// Thrown when BlockCipher blockSize is not correct. BlockSize needs to be a multiple of 8 bytes in length. Shorter lengths are not supported.
    /// </summary>
    public class InvalidBlockSizeException : Exception
    {
        public InvalidBlockSizeException()
        {

        }
        public InvalidBlockSizeException(string message) : base(message)
        {

        }
    }

    /// <summary>
    /// Thrown when plainText is not usable for creating cipherText
    /// </summary>
    public class PlainTextException : Exception
    {
        public PlainTextException()
        {
            
        }
        public PlainTextException(string message) : base(message)
        {

        }
        public override string Message
        {
            get
            {
                return "Exception, plainText not set correctly";
            }
        }
    }

    /// <summary>
    /// Thrown when cipherText is not usable for creating plainText
    /// </summary>
    public class CipherTextException : Exception
    {
        public CipherTextException()
        {

        }
        public CipherTextException(string message) : base(message)
        {

        }
        public override string Message
        {
            get
            {
                return "Exception, cipherText not set correctly";
            }
        }
    }
}