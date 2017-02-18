using System;
using CryptoPalChallenges;
using CryptoPalChallenges.Set1;
using CryptoPalChallenges.Set2;
using CryptoPalChallenges.Set3;
using Cipher;

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
            Set2.doChallenge14();

            Console.WriteLine();
            Console.WriteLine("All done. Press any key to exit.");
            Console.ReadKey();
        }
    }
}
