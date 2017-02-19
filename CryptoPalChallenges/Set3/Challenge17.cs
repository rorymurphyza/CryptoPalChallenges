using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cipher;
using Extensions;

namespace CryptoPalChallenges.Set3
{
    public partial class Set3
    {        
        public static void doChallenge17()
        {
            rnd = new Random();
            //generate the key
            GenerateAESChallengeKey();

            //Call the oracle and get back the cipherText and IV
            byte[] IV;
            byte[] cipherText = challenge17Oracle(out IV);

            //now we have the cipher text and IV, let's decrypt it and see what we get back
            bool validPadding = false;
            byte[] plainText = challenge17Decrypter(cipherText, IV, out validPadding);
            Console.WriteLine("Padding is {0}", validPadding ? "valid" : "invalid");
        }

        private static byte[] challenge17Oracle(out byte[] IV)
        {
            //select a random string from the selection
            string[] lines = File.ReadAllLines(@"..\..\..\CryptoPalChallenges\Files\Set3Challenge17.txt");
            List<byte[]> inputCipherText = new List<byte[]>();
            foreach (string s in lines)
                inputCipherText.Add(Convert.FromBase64String(s));

            //select a random line to be used for the rest of the challenge
            byte[] plainText = inputCipherText[rnd.Next(0, inputCipherText.Count)];

            //Encrypt it under the CBC mode
            BlockCipher cipher = new BlockCipher.CBCMode();
            cipher.plainText = plainText;
            cipher.key = ChallengeKey;
            cipher.padding = System.Security.Cryptography.PaddingMode.PKCS7;
            cipher.encrypt();
            IV = cipher.IV;
            return cipher.cipherText;
        }

        private static byte[] challenge17Decrypter(byte[] cipherText, byte[] IV, out bool validPadding)
        {
            var cipher = new BlockCipher.CBCMode();
            cipher.cipherText = cipherText;
            cipher.IV = IV;
            cipher.key = ChallengeKey;
            cipher.decrypt();
            cipher.plainText = cipher.isValidPadding(out validPadding);

            return cipher.plainText;
        }
    }
}
