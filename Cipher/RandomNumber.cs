using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cipher
{
    /// <summary>
    /// Contains RandomNumber generators for use. Uses inheritance for structuring
    /// </summary>
    public abstract class RandomNumber
    {
        public abstract ulong GetRnd();

        /// <summary>
        /// Implementation of the Mersenne Twister PRNG. Initialise object and call MersenneTwister.GetRnd() to get next random number.
        /// Default constructor seeds algorithm with output from C# Random() class
        /// </summary>
        public class MersenneTwister : RandomNumber
        {
            private const ulong n = 312;
            private const ulong a = 0xB5026F5AA96619E9;
            private const ulong m = 156;

            private const ulong f = 6364136223846793005;
            private const int w = 64;

            private const int u = 29;
            private const ulong d = 0x5555555555555555;
            private const int s = 17;
            private const ulong b = 0x71D67FFFEDA60000;
            private const int t = 37;
            private const ulong c = 0xFFF7EEE000000000;
            private const int l = 43;

            private const ulong lowerMask = 0x7FFFFFFF;
            private const ulong upperMask = ~lowerMask;

            private ulong index = n + 1;
            private ulong[] MT = new ulong[n];

            /// <summary>
            /// Default constructor. Seeds algorithm with Random object of int.size range.
            /// </summary>
            public MersenneTwister()
            {
                Random rnd = new Random();
                this.seed_mt((ulong)rnd.Next(int.MinValue, int.MaxValue));
            }

            /// <summary>
            /// Constructor to seed with ulong value. 
            /// </summary>
            /// <param name="seed"></param>
            public MersenneTwister(ulong seed)
            {
                this.seed_mt(seed);
            }

            private void seed_mt(ulong seed)
            {
                index = n;
                MT[0] = seed;

                for (ulong i = 1; i < n; ++i)
                    MT[i] = (f * (MT[i - 1] ^ (MT[i - 1] >> (w - 2))) + i);
            }

            /// <summary>
            /// Get the next random number from the generator.
            /// </summary>
            /// <returns></returns>
            public override ulong GetRnd()
            {
                if (index >= n)
                {
                    if (index > n)
                        throw new Exception("Generator hasn't been seeded");
                    this.twist();
                }

                ulong y = MT[index];
                y = y ^ ((y >> u) & d);
                y = y ^ ((y << s) & b);
                y = y ^ ((y << t) & c);
                y = y ^ (y >> l);

                ++index;

                return y;
            }

            private void twist()
            {
                for (ulong i = 0; i < n; ++i)
                {
                    ulong x = (MT[i] & upperMask) + (MT[(i + 1) % n] & lowerMask);
                    ulong xA = x >> 1;

                    if (x % 2 != 0)
                        xA = xA ^ a;
                    MT[i] = MT[(i + m) % n] ^ xA;
                }
                index = 0;
            }
        }
                
    }
}
