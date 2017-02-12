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
        /// Extension method to convert Unicode-encoded byte array into string
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string toString(this byte[] input)
        {
            return System.Text.Encoding.ASCII.GetString(input);
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

        /// <summary>
        /// Extension method to convert byte[] into Base64-encoded string
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string toBase64String(this byte[] input)
        {
            return System.Convert.ToBase64String(input);
        }

        /// <summary>
        /// Extension method to convert Base64 string to byte[]
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static byte[] base64ToByteArray(this string input)
        {
            return Convert.FromBase64String(input);
        }

        /// <summary>
        /// Extension method to convert given Unicode string into equivalent byte array.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static byte[] toByteArray(this string input)
        {
            byte[] output = new byte[input.Length];
            for (int i = 0; i < output.Length; i++)
            {
                char c = input.Substring(i, 1)[0];
                output[i] = Convert.ToByte(c);
            }

            return output;
        }

        /// <summary>
        /// Extension method to convert byte[] into hex-encoded output string.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string toHexString(this byte[] input)
        {
            StringBuilder hex = new StringBuilder();
            foreach (byte b in input)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
    }    
}
