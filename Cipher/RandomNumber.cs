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
        /// <summary>
        /// Get the next random ulong from the generator.
        /// </summary>
        /// <returns></returns>
        public abstract ulong GetUlongRnd();

        /// <summary>
        /// Get the next random uint from the generator
        /// </summary>
        /// <returns></returns>
        public abstract uint GetUintRnd();

        /// <summary>
        /// Implementation of the Mersenne Twister PRNG in 32-bit mode. Initialise object and call MersenneTwister.GetUlongRnd() to get next random number.
        /// Default constructor seeds algorithm with output from C# Random() class
        /// </summary>
        public class MersenneTwister : RandomNumber
        {
            private const uint f = 1812433253;
            private const uint n = 624;
            private const uint a = 0x9908B0DF;
            private const uint m = 397;

            private const uint b = 0x9D2C5680;
            private const uint c = 0xEFC60000;
            private const int l = 18;
            private const int s = 7;
            private const int t = 15;
            private const int u = 11;

            private const uint lowerMask = 0x7FFFFFFF;
            private const uint upperMask = ~lowerMask;

            private uint index;
            private uint[] MT = new uint[n];

            /// <summary>
            /// Default constructor. Seeds algorithm with Random object of int.size range.
            /// </summary>
            public MersenneTwister()
            {
                Random rnd = new Random();
                this.seed_mt((uint)rnd.Next(int.MinValue, int.MaxValue));
            }

            /// <summary>
            /// Constructor to seed with ulong value. 
            /// </summary>
            /// <param name="seed"></param>
            public MersenneTwister(int seed)
            {
                this.seed_mt((uint)seed);
            }

            private void seed_mt(uint seed)
            {
                index = n;
                MT[0] = seed;
                for (int i = 1; i < n; i++)
                    MT[i] = (uint)(f * (MT[i - 1] ^ (MT[i - 1] >> 30)) + i);
            }
            
            private void twist()
            {
                uint x, xA;

                for (int i = 0; i < n; i++)
                {
                    x = (MT[i] & upperMask) + (MT[(i + 1) % n] & lowerMask);
                    xA = x >> 1;
                    if (x % 2 != 0)
                        xA ^= a;
                    MT[i] = MT[(i + m) % n] ^ xA;
                }
                index = 0;
            }

            public override ulong GetUlongRnd()
            {
                throw new NotImplementedException();
            }

            public override uint GetUintRnd()
            {
                uint i = index;

                if (index >= n)
                {
                    this.twist();
                    i = index;
                }

                uint y = MT[i];
                index = i + 1;

                y ^= (MT[i] >> u);
                y ^= (y << s) & b;
                y ^= (y >> t) & c;
                y ^= (y >> l);

                return y;
            }
        }

        /// <summary>
        /// Implementation of the Mersenne Twister PRNG in 64-bit mode. Initialise object and call MersenneTwister.GetUlongRnd() to get next random number.
        /// Default constructor seeds algorithm with output from C# Random() class
        /// </summary>
        public class MersenneTwister64 : RandomNumber
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
            public MersenneTwister64()
            {
                Random rnd = new Random();
                this.seed_mt((ulong)rnd.Next(int.MinValue, int.MaxValue));
            }

            /// <summary>
            /// Constructor to seed with ulong value. 
            /// </summary>
            /// <param name="seed"></param>
            public MersenneTwister64(ulong seed)
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
            public override ulong GetUlongRnd()
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

            public override uint GetUintRnd()
            {
                throw new NotImplementedException();
            }
        }
                
    }
}
