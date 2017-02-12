using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cipher;
using Extensions;

namespace CryptoPalChallenges.Set1
{
    public partial class Set1
    {
        public static void doChallenge8()
        {
            //Each line in the given file represents a seperate cipherText, so we need to treat them as difference inputs
            string[] lines = File.ReadAllLines(@"..\..\..\CryptoPalChallenges\Files\Set1Challenge8.txt");

            foreach (string l in lines)
            {
                BlockCipher cipher = new BlockCipher.ECBMode();
                cipher.cipherText = l.toByteArray();
                if (cipher.isECBMode())
                {
                    Console.WriteLine("Found duplicate blocks in ciphertext.");
                    Console.WriteLine("Ciphertext is: ");
                    Console.WriteLine(l);
                }
            }
        }
    }
}
