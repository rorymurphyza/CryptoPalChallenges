using System;
using CryptoPalChallenges;
using CryptoPalChallenges.Set1;
using CryptoPalChallenges.Set2;
using CryptoPalChallenges.Set3;
using Cipher;
using Extensions;

namespace Shell
{
    class Program
    {
        static void Main(string[] args)
        {
            //Workers.doChallenge3();     //Set 1, Challenge 3 worker and solution
            //Workers.doChallenge4();       //Set 1, Challenge 4 worker and solution
            //Encrypter.RepeatingXOR("Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal", "ICE");    //Set 1, Challenge 5
            //Workers.BreakRepeatingXOR();    //Set 1, Challenge 6 worker and solution
            //Workers.AESinECBMode();         //Set 1, Challange 7 worker and solution
            //Workers.DetectECBEncoding();      //Set 1, Challenge 8 worker and solution, deprecated
            //Set1.doChallenge8();              //Set 1, Challenge 8 worker and solution

            //Set2.doChallenge10();
            //Set2.doChallenge11();
            //Set2.doChallenge12();
            //Set2.doChallenge13();
            //Set2.doChallenge14();
            //Challenge 15 added to BlockCipher, check unit tests for results
            //Set2.doChallenge16();

            //Set3.doChallenge17();

            string input64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
            CTRMode cipher = new CTRMode();
            cipher.cipherText = input64.base64ToByteArray();
            cipher.key = "YELLOW SUBMARINE".toByteArray();
            cipher.decrypt();
            string output = cipher.plainText.toString();
            Console.WriteLine(cipher.plainText.toString());
            

            Console.WriteLine();
            Console.WriteLine("All done. Press any key to exit.");
            Console.ReadKey();
        }
    }
}
