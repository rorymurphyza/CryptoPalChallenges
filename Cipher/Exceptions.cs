using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cipher
{
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

    /// <summary>
    /// Thrown when IV is not the correct length.
    /// </summary>
    public class InvalidLengthIV : Exception
    {
        public InvalidLengthIV()
        {

        }
        public InvalidLengthIV(string message) : base(message)
        {

        }
        public override string Message
        {
            get
            {
                return "Invalid Length for IV, must be the same as blockSize";
            }
        }
    }

    /// <summary>
    /// Thrown when padding is not valid for cipherText
    /// </summary>
    public class InvalidPaddingException : Exception
    {
        public InvalidPaddingException()
        {

        }
        public InvalidPaddingException(string message) : base (message)
        {

        }
        public override string Message
        {
            get
            {
                return "PCKS#7 Padding is not valid for this cipherText";
            }
        }
    }

    /// <summary>
    /// Thrown when nonce length is incorrect. Nonce length should be half of blockSize
    /// </summary>
    public class InvalidLengthNonce : Exception
    {
        public InvalidLengthNonce()
        {

        }
        public InvalidLengthNonce(string message) : base(message)
        {

        }
        public override string Message
        {
            get
            {
                return "Invalid length nonce, is should be half of blockSize";
            }
        }
    }
}
