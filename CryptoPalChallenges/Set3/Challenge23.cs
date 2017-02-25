using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoPalChallenges.Set3
{
    public partial class Set3
    {
        public static void doChallenge23()
        {
            seed_mt(12);
            //we have the MT structure built at this point. our job is to populate a new structure to map this and thus replicate the internals

            int temperInput = MT[10];
            int temperOutput = temper(temperInput);    //temperOutput is derived from MT[i]

            int unTemperOutput = untemper(temperOutput); //should match temperInput
        }

        static uint n = 624;
        static int[] MT = new int[n];
        static uint f = 1812433253;
        static uint index;
        static int u = 11;
        static uint b = 0x9D2C5680;
        static uint c = 0xEFC60000;
        static int l = 18;
        static int s = 7;
        static int t = 15;

        private static void seed_mt(int seed)
        {
            index = n;
            MT[0] = seed;
            for (int i = 1; i < n; i++)
                MT[i] = (int)(f * (MT[i - 1] ^ (MT[i - 1] >> 30)) + i);
        }

        private static int temper(int i)
        {
            int y = i;

            y ^= (i >> u);
            y ^= (int)((y << s) & b);
            y ^= (int)((y << t) & c);
            y ^= (y >> l);

            return y;
        }

        private static int untemper(int y)
        {
            y = reverseRightBitshiftXOR(y, l);
            y = reverseLeftBitshiftXOR(y, t, c);
            y = reverseLeftBitshiftXOR(y, s, b);
            y = reverseRightBitshiftXOR(y, u);              

            return y;
        }

        private static int reverseRightBitshiftXOR(int value, int shift)
        {
            int i = 0;
            int result = 0;

            while (i * shift < 32)
            {
                int partMask = (-1 << (32 - shift)) >> (shift * i);
                int part = value & partMask;
                value ^= (part >> shift);
                result |= part;
                i++;
            }
            return result;
            //return (value ^ (value >> shift));
        }

        private static int reverseLeftBitshiftXOR(int input, int shift, uint mask)
        {
            int i = 0;
            int result = 0;

            while (i * shift < 32)
            {
                int mask1 = (-1 >> (32 - shift)) << (shift * i);
                int part = input & mask1;
                input ^= ((part << shift) & mask1);
                result |= part;
                i++;
            }
            return result;
        }
    }
}
