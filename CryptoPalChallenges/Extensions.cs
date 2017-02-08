using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoPalChallenges
{
    public static class Extensions
    {
        /// <summary>
        /// Extension method to convert ASCII-encoded byte array into string
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string toString(this byte[] input)
        {
            return System.Text.Encoding.Unicode.GetString(input);
        }

        /// <summary>
        /// Extension method to turn a string of hex bytes into a byte array for easy processing
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static byte[] hexToByteArray(this string input)
        {
            int numChars = input.Length;
            byte[] byteArray = new byte[numChars / 2];
            for (int i = 0; i < numChars; i = i + 2)
                byteArray[i / 2] = System.Convert.ToByte(input.Substring(i, 2), 16);
            return byteArray;
        }

        public static string toBase64String(this byte[] input)
        {
            return System.Convert.ToBase64String(input);
        }
    }    
}
