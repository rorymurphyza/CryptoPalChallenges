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
        public static void doChallenge16()
        {
            GenerateAESChallengeKey();
            string input = ";admin=true;";
            input = challenge14Formatter(input);

            #region start the attack
            byte[] newData = new byte[32];      //two blocks of data we are going to work with
            for (int i = 0; i < newData.Length; i++)
                newData[i] = (byte)'A';
            //use the oracle to get the ciphertext that we are going to manipulate
            var cipherText = oracle16(newData);

            //grab the third block from the ciphertext. we don't want the first two because we need enough space to insert our two new blocks
            byte[] blockToOverwrite = cipherText.Skip(32).Take(16).ToArray();
            blockToOverwrite = Utilities.XORByteArrays(blockToOverwrite, ";admin=true;;;;;".toByteArray()); //XOR the grabbed block with the string we want to insert, padded to a full block length
            blockToOverwrite = Utilities.XORByteArrays(blockToOverwrite, "AAAAAAAAAAAAAAAA".toByteArray()); //XOR with the contents we know are in the previous block, so the decryption works

            Array.Copy(blockToOverwrite, 0, cipherText, 32, 16);    //copy our new block into the cipherText array, after the first block we asked for earlier
            #endregion
            Console.WriteLine("admin=" + adminVerifier(cipherText).ToString());
        }

        internal static bool adminVerifier(byte[] cipherText)
        {
            BlockCipher cipher = new BlockCipher.CBCMode();
            cipher.key = ChallengeKey;
            cipher.cipherText = cipherText;
            cipher.decrypt();
            return cipher.cipherText.toString().Contains(";admin=true;");
        }

        internal static string challenge14Formatter(string input)
        {
            input = input.Replace(";", "").Replace("=", "");    //eat the ; and = characters to stop XSS
            string prepend = "comment1=cooking%20MCs;userdata=";
            string append = ";comment2=%20like%20a%20pound%20of%20bacon";
            return string.Format("{0}{1}{2}", prepend, input, append);            
        }

        internal static byte[] oracle16(byte[] input)
        {
            BlockCipher cipher = new BlockCipher.CBCMode();
            cipher.plainText = challenge14Formatter(input.toString()).toByteArray();
            cipher.key = ChallengeKey;
            cipher.encrypt();

            return cipher.cipherText;
        }
    }
}
