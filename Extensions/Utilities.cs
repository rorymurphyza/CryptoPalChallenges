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
            //check for the same lengths
            if (input1.Length > input2.Length)
            {
                byte[] tempArray = new byte[input2.Length];
                for (int i = 0; i < tempArray.Length; i++)
                {
                    tempArray[i] = input1[i];
                }
                input1 = tempArray;
            }
            else if (input2.Length > input1.Length)
            {
                byte[] tempArray = new byte[input1.Length];
                for (int i = 0; i < tempArray.Length; i++)
                {
                    tempArray[i] = input2[i];
                }
                input2 = tempArray;
            }

            byte[] output = new byte[input1.Length];
            for (int i = 0; i < output.Length; i++)
                output[i] = (byte)(input1[i] ^ input2[i]);

            return output;
        }
    }
}
