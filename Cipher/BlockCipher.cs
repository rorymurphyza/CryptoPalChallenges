using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cipher
{
    class BlockCipher
    {
        public class ECBMode : ICipher
        {
            public byte[] IV { get; set; }
            public byte[] key { get; set; }
            public byte[] cipherText { get; set; }
            public byte[] plainText { get; set; }
            public int blockSize { get; set; }

            public byte[] encrypt()
            {
                return new byte[1];
            }

            public byte[] decrypt()
            {
                return new byte[1];
            }
        }
    }
}
