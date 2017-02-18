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
            var prepend = new byte[numOfByteToPrepend];
            for (int i = 0; i < prepend.Length; i++)
                prepend[i] = (byte)rnd.Next(0x20, 0x7e);    //prepend only ASCII bytes for simplicity

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
    }
}
