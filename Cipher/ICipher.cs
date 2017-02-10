using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cipher
{
    interface ICipher
    {
        /// <summary>
        /// Initial values vector
        /// </summary>
        byte[] IV { get; set; }
        /// <summary>
        /// The predefined key
        /// </summary>
        byte[] key { get; set; }
        /// <summary>
        /// The cipher text to be decoded as required
        /// </summary>
        byte[] cipherText { get; set; }
        /// <summary>
        /// The plain text to be encoded as required
        /// </summary>
        byte[] plainText { get; set; }
        /// <summary>
        /// The block size of the cipher text, in bytes
        /// </summary>
        int blockSize { get; set; }

        byte[] encrypt();
        byte[] decrypt();
    }
}
