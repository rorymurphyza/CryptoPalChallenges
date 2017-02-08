using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CryptoPalChallenges
{
    public class Xor
    {
        /// <summary>
        /// Xor two equal length strings together. First used in Set 1, Challenge 2
        /// </summary>
        /// <param name="_input1"></param>
        /// <param name="_input2"></param>
        /// <returns></returns>
        public static string XorEqualLength(string input1, string input2)
        {
            byte[] input1Bytes = input1.hexToByteArray();
            byte[] input2Bytes = input2.hexToByteArray();
            byte[] outputBytes = new byte[input1Bytes.Length];
            for (int i = 0; i < outputBytes.Length; i++)
                outputBytes[i] = (byte)(input1Bytes[i] ^ input2Bytes[i]);
            return BitConverter.ToString(outputBytes).Replace("-", "").ToLower();
        }
    }

    public class Decrypter
    {
        public static Dictionary<byte, int> CalcCommonOccurences(string _input)
        {
            //Here we have a string encyrpted with a single byte as the key. Find the key
            byte[] byteArray = _input.hexToByteArray();
            //Array.Sort(byteArray);
            Dictionary<byte, int> occurences = new Dictionary<byte, int>();

            for (int i = 0; i < byteArray.Length; i++)
            {
                int updates = 1;
                foreach (var pair in occurences)
                {
                    if (pair.Key == byteArray[i])
                    {
                        updates = pair.Value + 1;

                    }
                }
                occurences.Remove(byteArray[i]);
                occurences.Add(byteArray[i], updates);
            }

            var sortedOccurences = from entry in occurences orderby entry.Value descending select entry;
            occurences = sortedOccurences.ToDictionary(pair => pair.Key, pair => pair.Value);

            return occurences;
        }
        
        public static string ShowCommonOccurences(string _input)
        {
            Dictionary<byte, int> occurences = CalcCommonOccurences(_input);

            StringBuilder toString = new StringBuilder();
            foreach (var pair in occurences)
            {
                toString.Append(string.Format("{0:X2}", pair.Key));
                toString.Append("       ");
                toString.Append(pair.Value);
                toString.Append(Environment.NewLine);
            }

            return toString.ToString();
        }

        public static string XorAgainstChar(string _input, char _key)
        {
            byte[] byteArray = _input.hexToByteArray();
            byte[] output = new byte[byteArray.Length];
            for (int i = 0; i < output.Length; i++)
            {
                output[i] = (byte)(byteArray[i] ^ _key);
            }

            char[] outputChar = new char[output.Length];
            for (int i = 0; i < outputChar.Length; i++)
            {
                outputChar[i] = Convert.ToChar(output[i]);
                if ((byte)outputChar[i] < 0x20)
                    outputChar[i] = 'X';
            }

            return new string(outputChar);
        }

        public static char XorCharAgainstChar(byte _x, byte _key)
        {
            byte result = (byte)(_x ^ _key);
            return Convert.ToChar(result);
        }

        public static string XorAgainstByte(string _input, byte _key)
        {
            char[] key = Encoding.ASCII.GetChars(new byte[] { _key });
            return XorAgainstChar(_input, key[0]);
        }

        public static int ScoreString(string _input)
        {
            int score = 0;
            foreach (char c in _input)
            {
                switch (c)
                {
                    case 'e':
                    case 'E':
                        score = score + 12;
                        break;
                    case 't':
                    case 'T':
                        score = score + 9;
                        break;
                    case 'a':
                    case 'A':
                        score = score + 8;
                        break;
                    case 'o':
                    case 'O':
                        score = score + 7;
                        break;
                    case 'i':
                    case 'I':
                        score = score + 6;
                        break;
                    case 'n':
                    case 'N':
                        score = score + 6;
                        break;
                    case ' ':
                        score = score + 5;
                        break;
                }
            }

            return score;
        }

        public static int CalculateHammingDistance(string _input1, string _input2)
        {
            byte[] input1Array = Utils.ConvertStringToByteArray(_input1);
            byte[] input2Array = Utils.ConvertStringToByteArray(_input2);

            int distance = 0;
            for (int i = 0; i < input1Array.Length; i++)
            {
                byte result = (byte)(input1Array[i] ^ input2Array[i]);
                while (result != 0)
                {
                    distance++;
                    result &= (byte)(result - 1);
                }
            }

            return distance;
        }

        public static int CalculateHammingDistanceByte(byte[] _input1, byte[] _input2)
        {
            char[] input1 = new char[_input1.Length];
            char[] input2 = new char[_input2.Length];
            for (int i = 0; i < input1.Length; i++)
            {
                input1[i] = Convert.ToChar(_input1[i]);
                input2[i] = Convert.ToChar(_input2[i]);
            }
            string block1 = new string(input1);
            string block2 = new string(input2);
            return CalculateHammingDistance(block1, block2);
        }

        public static byte[] XorByteArrayAgainstByte(byte[] _input, byte _key, Encoding encoding)
        {
            byte[] output = new byte[_input.Length];
            if (encoding == Encoding.ASCII)
            {
                for (int i = 0; i < output.Length; i++)
                {
                    byte result = (byte)(_input[i] ^ _key);
                    if ((result < 0x20) || (result > 0x7E))
                        result = 0x58;  //'X'
                    output[i] = result;
                }
            }
            else
            {
                for (int i = 0; i < output.Length; i++)
                    output[i] = 0x00;
            }

            return output;
        }

        public static int ScoreByteArray(byte[] _input)
        {
            int score = 0;
            foreach (byte b in _input)
            {
                switch (b)
                {
                    case (byte)'e':
                    case (byte)'E':
                        score = score + 12;
                        break;
                    case (byte)'t':
                    case (byte)'T':
                        score = score + 9;
                        break;
                    case (byte)'a':
                    case (byte)'A':
                        score = score + 8;
                        break;
                    case (byte)'o':
                    case (byte)'O':
                        score = score + 7;
                        break;
                    case (byte)'i':
                    case (byte)'I':
                        score = score + 6;
                        break;
                    case (byte)'n':
                    case (byte)'N':
                        score = score + 6;
                        break;
                    case (byte)' ':
                        score = score + 5;
                        break;
                }
            }
            return score;
        }
    }

    public class Encrypter
    {
        public static string RepeatingXOR(string _input, string _key)
        {
            byte[] inputArray = ConvertStringToHexString(_input);
            byte[] keyArray = ConvertStringToHexString(_key);

            byte[] output = new byte[inputArray.Length];
            int keyPosition = 0;
            for (int i = 0; i < output.Length; i++)
            {
                if (keyPosition >= 3)
                    keyPosition = 0;

                output[i] = (byte)(inputArray[i] ^ keyArray[keyPosition]);

                keyPosition++;
            }

            return BitConverter.ToString(output).Replace("-", "").ToLower();
        }

        public static byte[] RepeatingXORByteArray(byte[] _input, byte[] _key)
        {
            byte[] output = new byte[_input.Length];

            int keyPosition = 0;
            for (int i = 0; i < output.Length; i++)
            {
                if (keyPosition >= _key.Length)
                    keyPosition = 0;
                output[i] = (byte)(_input[i] ^ _key[keyPosition]);
                keyPosition++;
            }

            return output;
        }

        public static byte[] ConvertStringToHexString(string _input)
        {
            byte[] output = new byte[_input.Length];
            for (int i = 0; i < output.Length; i++)
            {
                char c = _input.Substring(i, 1)[0];
                output[i] = Convert.ToByte(c);
            }

            return output;
        }
    }

    public class Workers
    {
        public static void DetectECBEncoding()
        {
            string[] lines = File.ReadAllLines(@"..\..\..\CryptoPalChallenges\Files\Set1Challenge8.txt");
            List<byte[]> encryptedLines = new List<byte[]>();
            foreach (string l in lines)
            {
                //encryptedLines.Add(Convert.FromBase64String(l));
                encryptedLines.Add(l.hexToByteArray());
            }

            //Now, we want to attack ECB by checking which line has ECB being used
            //ECB is stateless, so any repeating plain text will give the same cyphertext
            //This means that we can looking for repeating patterns to see if ECB has been used
            foreach (byte[] cypherText in encryptedLines)
            {
                List<byte[]> blocks = new List<byte[]>();
                for (int i = 0; i < cypherText.Length; i = i + 16)
                {
                    blocks.Add(cypherText.Skip(i).Take(16).ToArray());
                }
                List<byte[]> uniques = new List<byte[]>();
                foreach (byte[] block in blocks)
                {
                    bool found = false;
                    foreach (byte[] compare in uniques)
                    {
                        if (Enumerable.SequenceEqual(block, compare))
                            found = true;
                    }
                    if (!found)
                        uniques.Add(block);
                }
                if (blocks.Count != uniques.Count)
                {
                    Console.WriteLine("Duplicate found");
                    StringBuilder output = new StringBuilder();
                    foreach (byte b in cypherText)
                        output.Append(Convert.ToChar(b));
                    Console.WriteLine(CryptoPalChallenges.Utils.ConvertByteArrayToHexString(cypherText));
                }
            }
        }

        public static void AESinECBMode()
        {
            string lines = File.ReadAllText(@"..\..\..\CryptoPalChallenges\Files\Set1Challenge7.txt");
            byte[] encryptedText = Convert.FromBase64String(lines);

            Console.WriteLine("Decrypting");

            RijndaelManaged Crypto = new RijndaelManaged();
            Crypto.Key = CryptoPalChallenges.Utils.ConvertStringToByteArray("YELLOW SUBMARINE");
            Crypto.Mode = CipherMode.ECB;
            Crypto.BlockSize = 128;
            Crypto.Padding = PaddingMode.PKCS7;

            ICryptoTransform Decrypter = Crypto.CreateDecryptor(Crypto.Key, Crypto.IV);

            MemoryStream MemStream = new MemoryStream(encryptedText);

            CryptoStream Stream = new CryptoStream(MemStream, Decrypter, CryptoStreamMode.Read);

            StreamReader Reader = new StreamReader(Stream);

            string plainText = Reader.ReadToEnd();
            Console.WriteLine(plainText);
        }

        public static void doChallenge4()
        {
            //Set 1, Challenge 4
            string[] lines = File.ReadAllLines(@"..\..\..\CryptoPalChallenges\Files\MultipleInputs.txt");

            DataTable dt = new DataTable();
            dt.Columns.Add("DecodedString", typeof(string));
            dt.Columns.Add("RawString", typeof(string));
            dt.Columns.Add("LineNumber", typeof(int));
            dt.Columns.Add("Key", typeof(byte));
            dt.Columns.Add("Score", typeof(int));

            int lineNumber = 0;
            foreach (string _input in lines)
            {
                //Let's set a base score of 100 and add a line to the dt if above this score
                for (byte i = 0; i < 0xFF; i++)
                {
                    string output = CryptoPalChallenges.Decrypter.XorAgainstChar(_input, Convert.ToChar(i));
                    int score = CryptoPalChallenges.Decrypter.ScoreString(output);
                    if (score > 100)
                        dt.Rows.Add(output, _input, lineNumber, i, score);
                }
                lineNumber++;
            }

            dt.DefaultView.Sort = "Score" + " " + "DESC";
            dt = dt.DefaultView.ToTable();
            foreach (DataRow dr in dt.Rows)
            {
                Console.Write(dr.Field<string>(0));
                Console.Write("     ");
                Console.Write(dr.Field<string>(1));
                Console.Write("     ");
                Console.Write(dr.Field<int>(2));
                Console.Write("     ");
                Console.Write(string.Format("0x{0}", (dr.Field<byte>(3)).ToString("X2")));
                Console.Write("     ");
                Console.Write(dr.Field<int>(4));
                Console.WriteLine();
            }
        }

        public static void doChallenge3()
        {
            //Set 1, Challenge 3
            DataTable dt = new DataTable();
            dt.Columns.Add("DecodedString", typeof(string));
            dt.Columns.Add("Key", typeof(byte));
            dt.Columns.Add("Score", typeof(int));

            string input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

            Dictionary<byte, int> occurences = CryptoPalChallenges.Decrypter.CalcCommonOccurences(input);

            string output = CryptoPalChallenges.Decrypter.ShowCommonOccurences(input);
            Console.WriteLine(output);

            //Now we want to find the key that will result in the most common occurence being part of ETAOIN
            List<byte> key = new List<byte>();
            for (byte i = 0; i < 0xFF; i++)
            {
                char result = CryptoPalChallenges.Decrypter.XorCharAgainstChar(occurences.Keys.First(), i);
                if ((result == 'E') || (result == 'e')
                    || (result == 'T') || (result == 't')
                    || (result == 'A') || (result == 'a')
                    || (result == 'O') || (result == 'o')
                    || (result == 'I') || (result == 'i')
                    || (result == 'N') || (result == 'n')
                    || (result == 'S') || (result == 's')
                    || (result == 'H') || (result == 'h')
                    || (result == 'R') || (result == 'r')
                    || (result == 'D') || (result == 'd')
                    || (result == 'L') || (result == 'l')
                    || (result == 'U') || (result == 'u')
                    || (result == ' '))
                    key.Add(i);
            }

            foreach (byte c in key)
            {
                string decodedString = CryptoPalChallenges.Decrypter.XorAgainstChar(input, Convert.ToChar(c));
                dt.Rows.Add(decodedString, c, CryptoPalChallenges.Decrypter.ScoreString(decodedString));
            }

            dt.DefaultView.Sort = "Score" + " " + "DESC";
            dt = dt.DefaultView.ToTable();
            foreach (DataRow dr in dt.Rows)
            {
                Console.Write(dr.Field<string>(0));
                Console.Write("         ");
                Console.Write(dr.Field<byte>(1));
                Console.Write("         ");
                Console.WriteLine(dr.Field<int>(2));
            }
        }

        public static void BreakRepeatingXOR()
        {
            List<string> probableKeys = new List<string>();

            //First, read in the cyphertext we are going to use
            string lines = File.ReadAllText(@"..\..\..\CryptoPalChallenges\Files\Set1Challenge6.txt");

            DataTable dt = new DataTable();
            dt.Columns.Add("keySize", typeof(int));
            dt.Columns.Add("distance", typeof(double));
            //Treat the entire cyphertext as a single block, turn it into bytes
            //We ALWAYS want to work in bytes
            byte[] decodedLines = Convert.FromBase64String(lines);

            //keySize of 2 doesn't make sense, it will always return the same Hamming Distance
            //Find the Hamming Distance for each keySize, save into DT
            for (int keySize = 3; keySize < 40; keySize++)
            {
                byte[] block1 = decodedLines.Skip(0).Take(keySize).ToArray();
                byte[] block2 = decodedLines.Skip(keySize).Take(keySize).ToArray();
                byte[] block3 = decodedLines.Skip(keySize * 2).Take(keySize).ToArray();
                byte[] block4 = decodedLines.Skip(keySize * 3).Take(keySize).ToArray();
                int distance1 = CryptoPalChallenges.Decrypter.CalculateHammingDistanceByte(block1, block2);
                int distance2 = CryptoPalChallenges.Decrypter.CalculateHammingDistanceByte(block1, block3);
                int distance3 = CryptoPalChallenges.Decrypter.CalculateHammingDistanceByte(block2, block3);
                int distance4 = CryptoPalChallenges.Decrypter.CalculateHammingDistanceByte(block1, block4);
                int distance5 = CryptoPalChallenges.Decrypter.CalculateHammingDistanceByte(block2, block4);
                int distance6 = CryptoPalChallenges.Decrypter.CalculateHammingDistanceByte(block3, block4);
                int totalDistance = distance1 + distance2 + distance3 + distance4 + distance5 + distance6;
                double averageDistance = (double)totalDistance / 6;
                double normalisedDistance = (double)(averageDistance) / keySize;
                dt.Rows.Add(keySize, normalisedDistance);
            }

            dt = orderDT(dt, "distance", "ASC");
            List<int> suggestedKeySizes = new List<int>();
            for (int i = 0; i < 3; i++)
                suggestedKeySizes.Add(dt.Rows[i].Field<int>(0));


            //Use the top 3 keySizes to try figure out the key
            foreach (int keySize in suggestedKeySizes)
            {
                StringBuilder sb = new StringBuilder();
                List<byte[]> transposedString = transposeCypherBlocks(decodedLines, keySize);
                foreach (byte[] encodedBytes in transposedString)
                {
                    //We now have a string of characters that were encoded with the same byte
                    //Run through each byte and create a string decoded with each possible byte
                    List<byte[]> decodedBytes = new List<byte[]>();
                    dt = new DataTable();
                    dt.Columns.Add("key", typeof(byte));
                    dt.Columns.Add("score", typeof(int));
                    for (byte i = 0; i < byte.MaxValue; i++)
                    {
                        byte[] temp = CryptoPalChallenges.Decrypter.XorByteArrayAgainstByte(encodedBytes, i, Encoding.ASCII);
                        decodedBytes.Add(temp);
                        dt.Rows.Add(i, CryptoPalChallenges.Decrypter.ScoreByteArray(temp));
                    }
                    dt = orderDT(dt, "score", "DESC");
                    byte decodedKey = (byte)dt.Rows[0]["key"];
                    char tempChar = (char)decodedKey;
                    sb.Append(tempChar.ToString());
                }
                probableKeys.Add(sb.ToString());
                //Console.WriteLine(sb.ToString());
            }

            //We know that the key in this case is probably a nice string, so let's score and see which is the most likely
            string key = "";
            /*
            This should work as a scoring function, but is too limited
            Shortcutting it for now, it can be made to work in the future
            foreach (string passKey in probableKeys)
            {
                
                
                int score = CryptoPalChallenges.Decrypter.ScoreString(passKey);
                if (score > max)
                {
                    key = passKey;
                    max = score;
                }
            }*/
            //key is now the passcode/key that we can use
            //We can now throw the encoded array through the Encrypter with the key and see what comes out.
            key = probableKeys[0];
            byte[] fullyDecoded = CryptoPalChallenges.Encrypter.RepeatingXORByteArray(decodedLines, CryptoPalChallenges.Utils.ConvertStringToByteArray(key));
            Console.WriteLine(CryptoPalChallenges.Utils.ConvertByteArrayToString(fullyDecoded));
        }

        public static List<byte[]> transposeCypherBlocks(byte[] decodedLines, int keySize)
        {
            //Break the cyphertext into keySize length arrays.
            //This should give the portions of cypher that were encoded with the key
            byte[,] cypherBlocks = new byte[decodedLines.Length / keySize, keySize];
            for (int i = 0; i < decodedLines.Length / keySize; i++)
            {
                for (int j = 0; j < keySize; j++)
                {
                    cypherBlocks[i, j] = decodedLines[(i * keySize) + j];
                }
            }
            //The first byte of each row should have been encoded with the same single character
            //If we get the first byte, we can then figure out the key for that byte
            //We can then repeat for each byte in the rows
            List<byte[]> toBeXoredAgainstChar = new List<byte[]>();
            for (int i = 0; i < keySize; i++)
            {
                byte[] temp = new byte[decodedLines.Length / keySize];
                for (int j = 0; j < decodedLines.Length / keySize; j++)
                {
                    temp[j] = cypherBlocks[j, i];
                }
                toBeXoredAgainstChar.Add(temp);
            }

            return toBeXoredAgainstChar;
        }

        internal static DataTable orderDT(DataTable dt, string colName, string ordering)
        {
            dt.DefaultView.Sort = colName + " " + ordering;
            dt = dt.DefaultView.ToTable();
            return dt;
        }
    }

    public partial class Utils
    {
        /// <summary>
        /// Send in a normal string, get back a byte[]
        /// </summary>
        /// <param name="_input"></param>
        /// <returns></returns>
        public static byte[] ConvertStringToByteArray(string _input)
        {
            byte[] output = new byte[_input.Length];
            for (int i = 0; i < output.Length; i++)
            {
                char c = _input.Substring(i, 1)[0];
                output[i] = Convert.ToByte(c);
            }

            return output;
        }

        /// <summary>
        /// Send in a base64 string, get back a string
        /// </summary>
        /// <param name="_input"></param>
        /// <returns></returns>
        public static string ConvertBase64ToString(string _input)
        {
            byte[] byteArray = Convert.FromBase64String(_input);
            return System.Text.Encoding.UTF8.GetString(byteArray);
        }

        /// <summary>
        /// Send in a base64 string, get back the hex string
        /// </summary>
        /// <param name="_input"></param>
        /// <returns></returns>
        public static string ConvertBase64ToHexString(string _input)
        {
            string input = ConvertBase64ToString(_input);
            byte[] byteArray = ConvertStringToHexString(input);
            StringBuilder sb = new StringBuilder();
            foreach (byte c in byteArray)
                sb.AppendFormat("{0:X2}", c);
            return sb.ToString().ToLower();
        }

        /// <summary>
        /// Send in a normal string, get back a byte[] of its hex representation
        /// </summary>
        /// <param name="_input"></param>
        /// <returns></returns>
        public static byte[] ConvertStringToHexString(string _input)
        {
            byte[] output = new byte[_input.Length];
            for (int i = 0; i < output.Length; i++)
            {
                char c = _input.Substring(i, 1)[0];
                output[i] = Convert.ToByte(c);
            }

            return output;
        }

        /// <summary>
        /// Send in a byte array of ASCII encoded data, get back the string it represents
        /// </summary>
        /// <param name="_input"></param>
        /// <returns></returns>
        public static string ConvertByteArrayToString(byte[] _input)
        {
            return System.Text.Encoding.ASCII.GetString(_input);
        }

        /// <summary>
        /// Send in a byte[], get back the representation as a string 
        /// </summary>
        /// <param name="_input"></param>
        /// <returns></returns>
        public static string ConvertByteArrayToHexString(byte[] _input)
        {
            StringBuilder hex = new StringBuilder();
            foreach (byte b in _input)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
    }
}
