using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cipher;

namespace CryptoPalChallenges.Set3
{
    public partial class Set3
    {
        public static void doChallenge22()
        {
            //verify that the seed works to produce the same output
            //verifyBadSeed();

            Random rnd = new Random();
            int originalSeed = rnd.Next(int.MinValue, int.MaxValue);

            RandomNumber r = new RandomNumber.MersenneTwister(originalSeed);
            uint randomisedNumber = r.GetUintRnd();
            int bruteforcedSeed = bruteforceSeed(randomisedNumber);

            Console.WriteLine();
            Console.WriteLine("Original seed: " + originalSeed + ". Bruteforced seed: " + bruteforcedSeed);
        }

        internal static int bruteforceSeed(uint originalNumber)
        {
            //we want to see if we can find the randomised seed by brtue force here
            //we are concerned with how long this takes, so let's put a timer in place
            DateTime startTime = DateTime.Now;

            Console.WriteLine("Bruteforcing");
            RandomNumber rnd;
            uint randomNumber;
            int seed = 0;
            bool found = false;
            for (int i = int.MinValue; i < int.MaxValue; i++)
            {
                rnd = new RandomNumber.MersenneTwister(i);
                randomNumber = rnd.GetUintRnd();
                if (randomNumber == originalNumber)
                {
                    found = true;
                    seed = i;
                    break;
                }
            }

            if (found)
            {
                Console.WriteLine("Bruteforce done, seed found");
                Console.WriteLine("Total time: " + (DateTime.Now - startTime).Seconds + "seconds");
                return seed;
            }
            return 0;
        }

        internal static void verifyBadSeed()
        {
            //in theory, we should get the same number over again. in this, we get a repeat at position 72530
            RandomNumber rnd = new RandomNumber.MersenneTwister(12);
            uint seedValue = rnd.GetUintRnd();
            uint[] randoms = new uint[100000];
            for (int i = 0; i < randoms.Length; i++)
            {
                uint nextValue = rnd.GetUintRnd();
                //scan through randoms to see if we already have this number
                for (int j = 0; j < i; j++)
                {
                    if (randoms[j] == nextValue)
                        Console.WriteLine("Found collision at i=" + i + ", j=" + j);
                }
                randoms[i] = nextValue;

                //let's see what happens if we seed two different objects and get the first rnd
                seedValue = 12;
                RandomNumber rnd1 = new RandomNumber.MersenneTwister((int)seedValue);
                uint random1 = rnd1.GetUintRnd();

                RandomNumber rnd2 = new RandomNumber.MersenneTwister((int)seedValue);
                uint random2 = rnd2.GetUintRnd();
            }
        }
    }
}
