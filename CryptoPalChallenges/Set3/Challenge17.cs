using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoPalChallenges.Set3
{
    public partial class Set3
    {
        
        public static void doChallenge17()
        {
            rnd = new Random();
            //generate the key
            ChallengeKey = BlockCipherdep.generateRandomAESKey();

            //Call the oracle and get back the cipherText and IV
            byte[] IV;
            byte[] cipherText = challenge17Oracle(out IV);

            //now we have the cipher text and IV, let's decrypt it and see what we get back
            byte[] plainText = challenge17Decrypter(cipherText, IV);
            //check padding is valid and remove it
            bool validPadding;
            plainText = Utils.isValidPadding(plainText, out validPadding);

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
            var cipher = new BlockCipherdep(ChallengeKey);
            cipher.plainText = plainText;
            BlockCipherdep.CBCMode.encrypt(cipher);

            IV = cipher.IV;
            return cipher.cipherText;
        }

        private static byte[] challenge17Decrypter(byte[] cipherText, byte[] IV)
        {
            var cipher = new BlockCipherdep(ChallengeKey);
            cipher.cipherText = cipherText;
            cipher.IV = IV;
            BlockCipherdep.CBCMode.decrypt(cipher);

            return cipher.plainText;
        }
    }
}
