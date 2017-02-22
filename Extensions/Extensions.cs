using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Extensions
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
            if (input[input.Length - 1] == 0x00)
            {
                byte bytesDropped = 0;
                for (int i = input.Length - 1; i > 0; i--)
                {
                    if (input[i] == 0x00)
                        bytesDropped++;
                }
                byte[] output = new byte[input.Length - bytesDropped];
                for (int i = 0; i < output.Length; i++)
                    output[i] = input[i];
                return System.Text.Encoding.ASCII.GetString(output);
            }
            else if (input[input.Length - 1] < 0x0F)
            {
                byte bytesDropped = input[input.Length - 1];
                byte[] output = new byte[input.Length - bytesDropped];
                for (int i = 0; i < output.Length; i++)
                    output[i] = input[i];
                return System.Text.Encoding.ASCII.GetString(output);
            }

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

        /// <summary>
        /// Extension method to convert byte[] into a List of block, given blockSize
        /// </summary>
        /// <param name="input"></param>
        /// <param name="blockSize"></param>
        /// <returns></returns>
        public static List<byte[]> toList(this byte[] input, int blockSize)
        {
            List<Byte[]> output = new List<byte[]>();
            byte[] array = new byte[blockSize];

            for (int i = 0; i < input.Length; i = i + blockSize)
            {
                array = input.Skip(i).Take(blockSize).ToArray();
                output.Add(array);
            }

            return output;
        }

        /// <summary>
        /// Extension method to turn List of byte[] back to byte[]
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static byte[] toByteArray(this List<byte[]> input)
        {
            int totalLength = 0;
            foreach (byte[] block in input)
                totalLength += block.Length;

            byte[] output = new byte[totalLength];
            int firstBlockLength = input[0].Length;
            for (int block = 0; block < input.Count; block++)
            {
                for (int b = 0; b < input[block].Length; b++)
                {
                    output[block * firstBlockLength + b] = input[block][b];
                }
            }
            return output;
        }
    }
}
