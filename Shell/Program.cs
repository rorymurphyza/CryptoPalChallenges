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
            //Challenge 18 added to BlockCipher class as CTRMode. Check unit tests for results.
            //Set3.doChallenge19();
            //Challenge 20 inadvertantly solved when doing Challenge 19. See the code there
            //Challenge 21 added to RandomNumber class. No unit tests done
            //Set3.doChallenge22();
            Set3.doChallenge23();

            Console.WriteLine();
            Console.WriteLine("All done. Press any key to exit.");
            Console.ReadKey();
        }
    }
}
