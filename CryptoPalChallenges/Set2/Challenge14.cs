using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cipher;
using Extensions;

namespace CryptoPalChallenges.Set2
{
    public partial class Set2
    {
        public static void doChallenge14()
        {
            GenerateAESChallengeKey();

            string input = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            var cipherText = oracle14(input.toByteArray());

            BlockCipher ecb = new BlockCipher.ECBMode();
            ecb.cipherText = cipherText;
            int blockSize = ecb.findBlockSize();
            bool isECB = ecb.isECBMode();

            #region find prefix length
            //find length of prefix. start with two blocks of identical plaintext. prepend other byte to this until we get two identical blocks of ciphertext.
            int prefixLength = 0;
            int blockPosition = 0;
            byte[] plainText;
            for (int j = 0; j < 100; j++)   //assume prefix is less than 100 bytes
            {
                plainText = new byte[blockSize * 2 + j];     //blocksize*2 gives the identical blocks
                for (int i = 0; i < blockSize; i++)     //add in the identical blocks
                {
                    plainText[i] = (byte)'A';
                    plainText[i + blockSize] = (byte)'A';
                }
                for (int i = blockSize * 2; i < plainText.Length; i++)  //add in the extra bytes as needed
                    plainText[i] = (byte)'A';
                cipherText = oracle14(plainText);
                if (findIdenticalCipherTextBlocks(cipherText, blockSize, out blockPosition))
                {
                    prefixLength = j;   //this is the number of bytes we had to add
                    break;
                }
            }
            //if we take the number of bytes we had to add, and prepend this as padding to our identical blocks, we can find the length properly
            plainText = new byte[blockSize * 2 + prefixLength];
            for (int i = 0; i < prefixLength; i++)
                plainText[i] = (byte)'\0';
            for (int i = prefixLength; i < plainText.Length; i++)
                plainText[i] = (byte)'A';
            cipherText = oracle14(plainText);
            findIdenticalCipherTextBlocks(cipherText, blockSize, out blockPosition);
            prefixLength = blockSize * blockPosition + (blockSize - prefixLength);
            Console.WriteLine("Prefix length is: " + prefixLength);
            #endregion

            #region break target-bytes
            //this is exactly the same as was done for Challenge 12, I will return and complete this.
            #endregion
        }

        internal static byte[] oracle14(byte[] input)
        {
            byte[] plainText = oracle14ByteAdder(input);

            BlockCipher cipher = new BlockCipher.ECBMode();
            cipher.key = ChallengeKey;
            cipher.plainText = plainText;
            cipher.encrypt();

            return cipher.cipherText;
        }

        private static byte[] oracle14ByteAdder(byte[] input)
        {
            int numOfByteToPrepend = rnd.Next(5, 20);
            var prepend = "This is the prepend text.".toByteArray();

            string append64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
            byte[] append = append64.base64ToByteArray();

            byte[] output = new byte[prepend.Length + input.Length + append.Length];
            for (int i = 0; i < prepend.Length; i++)
                output[i] = prepend[i];
            for (int i = prepend.Length; i < (prepend.Length + input.Length); i++)
                output[i] = input[i - prepend.Length];
            for (int i = (prepend.Length + input.Length); i < output.Length; i++)
                output[i] = append[i - prepend.Length - input.Length];

            return output;
        }

        public static bool findIdenticalCipherTextBlocks(byte[] cipherText, int blockSize, out int blockPosition)
        {
            //return true if we have two sucessive blocks of ciphertext that are exactly equal
            var blocks = cipherText.toList(blockSize);
            for (int i = 0; i < blocks.Count - 2; i++)
            {
                if (blocks[i].toHexString().Equals(blocks[i + 1].toHexString()))
                {
                    blockPosition = i - 1;  //we want to know the number of blocks before we found the two identical blocks
                    return true;
                }
            }
            blockPosition = 0;
            return false;
        }
    }
}
