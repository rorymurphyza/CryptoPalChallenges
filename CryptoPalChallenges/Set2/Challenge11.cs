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
        public static void doChallenge11()
        {
            GenerateAESChallengeKey();

            byte[] cipherText = null;

            //Just for testing, let's run this 10 times to see what out results look like, especially since we have the out bool to look at
            string input = "abcdefghijklmnopqrstuvwyxz123456abcdefghijklmnopqrstuvwyxz123456abcdefghijklmnopqrstuvwyxz123456";
            for (int i = 0; i < 10; i++)
            {
                bool isECB;
                cipherText = oracle(input, out isECB);

                //now, check it using our BlockCipher object
                BlockCipher cipher = new BlockCipher.ECBMode();
                cipher.cipherText = cipherText;
                bool validECB = cipher.isECBMode();

                Console.Write("Is ECB: " + isECB);
                Console.Write("     ");
                Console.WriteLine("ECB detected: " + validECB);
            }
        }

        internal static  byte[] oracle(string input, out bool isECB)   //The out statement is to check that we are detecting correctly, proper oracle shouldn't have it
        {
            byte[] plainText = addRandomBytes(input.toByteArray());

            int encryptionMethod = rnd.Next(0, 2);
            BlockCipher cipher;
            if (encryptionMethod == 0)  //use ECB mode
            {
                cipher = new BlockCipher.ECBMode();
                isECB = true;
            }
            else if (encryptionMethod == 1) //use CBC mode
            {
                cipher = new BlockCipher.CBCMode();
                isECB = false;
            }
            else
            {
                isECB = false;
                return null;
            }                

            cipher.key = ChallengeKey;
            cipher.plainText = plainText;
            cipher.encrypt();

            return cipher.cipherText;
        }

        private static byte[] addRandomBytes(byte[] input)
        {
            Random rnd = new Random();
            int numberToBePrepended = rnd.Next(5, 10);
            int numberToBeAppended = rnd.Next(5, 10);

            byte[] output = new byte[numberToBePrepended + input.Length + numberToBeAppended];
            for (int i = 0; i < numberToBePrepended; i++)
                output[i] = (byte)(rnd.Next(byte.MinValue, byte.MaxValue));
            for (int i = numberToBePrepended; i < (numberToBePrepended + input.Length); i++)
                output[i] = input[i - numberToBePrepended];
            for (int i = (numberToBePrepended + input.Length); i < (numberToBePrepended + input.Length + numberToBeAppended); i++)
                output[i] = (byte)(rnd.Next(byte.MinValue, byte.MaxValue));

            return output;
        }
    }
}
