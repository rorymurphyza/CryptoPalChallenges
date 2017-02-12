using Cipher;
using Extensions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoPalChallenges.Set2
{
    public partial class Set2
    {
        public static void doChallenge10()
        {
            string lines = File.ReadAllText(@"..\..\..\CryptoPalChallenges\Files\Set2Challenge10.txt");

            BlockCipher cipher = new BlockCipher.CBCMode();
            cipher.key = "YELLOW SUBMARINE".toByteArray();
            cipher.cipherText = lines.base64ToByteArray();
            cipher.decrypt();

            Console.WriteLine(cipher.plainText.toString());
        }
    }
}
