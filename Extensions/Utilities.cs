using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Extensions
{
    public class Utilities
    {
        /// <summary>
        /// XOR two equal length input against eachother
        /// </summary>
        /// <param name="input1"></param>
        /// <param name="input2"></param>
        /// <returns></returns>
        public static byte[] XORByteArrays(byte[] input1, byte[] input2)
        {
            byte[] output = new byte[input1.Length];
            for (int i = 0; i < output.Length; i++)
                output[i] = (byte)(input1[i] ^ input2[i]);

            return output;
        }
    }
}
