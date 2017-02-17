using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Extensions;
using Cipher;

namespace CryptoPalChallenges.Set2
{
    public partial class Set2
    {
        public static void doChallenge12()
        {
            //create single key for use
            GenerateAESChallengeKey();

            int blockSize = findBlockSize();

            //detect ECB mode
            BlockCipher ecb = new BlockCipher.ECBMode();
            string inputECB = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            ecb.cipherText = inputECB.toByteArray();
            bool isECB = ecb.isECBMode();

            if (isECB)
            {
                attackOracle12(blockSize);
                Console.WriteLine(attackOracle12(blockSize));
            }
            else
            {
                Console.WriteLine("Looks like the oracle isn't using ECB mode :(");
            }
        }

        internal static byte[] oracle12(byte[] input) 
        {
            byte[] plainText = appendToPlainText(input);

            BlockCipher cipher = new BlockCipher.ECBMode();
            cipher.key = ChallengeKey;
            cipher.plainText = plainText;
            cipher.encrypt();

            return cipher.cipherText;
        }

        private static byte[] appendToPlainText(byte[] input)
        {
            string append64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
            byte[] append = append64.base64ToByteArray();

            byte[] output = new byte[input.Length + append.Length];
            for (int i = 0; i < input.Length; i++)
                output[i] = input[i];
            for (int i = input.Length; i < (input.Length + append.Length); i++)
                output[i] = append[i - input.Length];

            return output;
        }

        internal static int findBlockSize()
        {
            int suspectedBlockSize = 0;
            int confirmedBlockSize = 0;
            bool foundSuspect = false;

            //Let's call the oracle with an ever-increasing string until the ciphertext gets longer. 
            StringBuilder sb = new StringBuilder("A");  
            for (int i = 1; i < (256 / 8); i++)     //(256/8) will allows us to check up to 256-bit blockSizes
            {
                int currentPlainLength = sb.ToString().Length;
                byte[] cipherText = oracle12(sb.ToString().toByteArray());
                int currentCipherLength = cipherText.Length;
                if (!(foundSuspect) && currentCipherLength > suspectedBlockSize)
                {
                    suspectedBlockSize = currentCipherLength;
                    foundSuspect = true;
                }
                if (foundSuspect && (currentCipherLength > suspectedBlockSize))
                {
                    confirmedBlockSize = currentCipherLength;
                    break;
                }
                sb.Append("A");
            }

            return confirmedBlockSize - suspectedBlockSize;
        }

        internal static string attackOracle12(int blockSize)
        {
            //find the nullCipher, ie. what will be returned when we don't give the oracle an input
            byte[] nullCipher = oracle12("".toByteArray());

            //the byte array we will now populate, should be the same length as the nullCipher as this will be filled with the characters from the nullCipher as we crack it
            byte[] retrievedBytes = new byte[nullCipher.Length];
            for (int i = 0; i < retrievedBytes.Length; i++)     //pre-populate the entire array
                retrievedBytes[i] = (byte)'A';
            
            for (int i = nullCipher.Length - 1; i >= 0; i--)
            {
                //build up the required dictionary
                var byteDictionary = buildByteDictionary(retrievedBytes);
                //take the retrievedBytes, knock off the last i amount and oracle it
                byte[] oracleInput = retrievedBytes.Take(i).ToArray();
                byte[] oracleOutput = oracle12(oracleInput);
                //now, take only the nullCipher.length worth of the oracleOutput
                byte[] toBeCracked = oracleOutput.Take(nullCipher.Length).ToArray();
                //run through the dictionary and see if we can find a match
                if (byteDictionary.ContainsKey(toBeCracked.toHexString()))
                    retrievedBytes = byteDictionary[toBeCracked.toHexString()].hexToByteArray();
                else
                    retrievedBytes[nullCipher.Length - 1] = (byte)'X';
                retrievedBytes = updateRetrievedBytes(retrievedBytes);
            }
            return retrievedBytes.toString();
        }
        
        internal static Dictionary<string, string> buildByteDictionary(byte[] retrievedBytes)
        {
            var byteDictionary = new Dictionary<string, string>();
            for (byte i = 0x00; i <= 0x7E; i++)
            {
                retrievedBytes[retrievedBytes.Length - 1] = i;
                byte[] byteCipher = oracle12(retrievedBytes).Take(retrievedBytes.Length).ToArray();
                byteDictionary.Add(byteCipher.toHexString(), retrievedBytes.toHexString());
            }

            return byteDictionary;
        }        

        internal static byte[] updateRetrievedBytes(byte[] input)
        {
            byte[] output = new byte[input.Length];
            for (int i = 0; i < output.Length - 1; i++)
                output[i] = input[i + 1];
            output[output.Length - 1] = (byte)'A';

            return output;
        }
    }
}
