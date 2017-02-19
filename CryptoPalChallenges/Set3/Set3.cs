using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoPalChallenges.Set3
{
    public partial class Set3
    {
        private static Random rnd = new Random();
        private static byte[] ChallengeKey;

        private static void GenerateAESChallengeKey()
        {
            byte[] key = new byte[16];
            for (int i = 0; i < key.Length; i++)
                key[i] = (byte)rnd.Next(byte.MinValue, byte.MaxValue);
            ChallengeKey = key;
        }
    }
}
