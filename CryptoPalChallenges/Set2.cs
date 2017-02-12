using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoPalChallenges
{
    class Set2dep
    {
    }

    public class BlockCipherdep
    {
        /// <summary>
        /// Initial values vector
        /// </summary>
        public byte[] IV { get; set; }
        /// <summary>
        /// The predefined key
        /// </summary>
        public byte[] key { get; set; }
        /// <summary>
        /// The cipher text to be decoded as required
        /// </summary>
        public byte[] cipherText { get; set; }
        /// <summary>
        /// The plain text to be encoded as required
        /// </summary>
        public byte[] plainText { get; set; }
        /// <summary>
        /// The block size of the cipher text, in bytes
        /// </summary>
        public int blockSize { get; set; }

        public BlockCipherdep() { }

        /// <summary>
        /// Constructor for standard settings and key as the input. Uses a 0x00 IV
        /// </summary>
        /// <param name="key"></param>
        public BlockCipherdep(byte[] _key)
        {
            //set up IV of all zeroes
            byte[] iv = new byte[16];
            for (int i = 0; i < iv.Length; i++)
                iv[i] = 0x00;
            IV = iv;

            key = _key;

            blockSize = _key.Length;
        }

        /// <summary>
        /// Implementation of the CBC Mode Block cipher. Contains functions for both encyrption and decryption
        /// </summary>
        public class CBCMode
        {
            /// <summary>
            /// Decrypt the given cipher text
            /// </summary>
            /// <param name="cipherText"></param>
            /// <returns></returns>
            public static void decrypt(BlockCipherdep cipher)
            {
                byte[] plainText = new byte[cipher.cipherText.Length];
                //Break the cipher text into blocks
                List<byte[]> cipherBlocks = new List<byte[]>();
                for (int i = 0; i < cipher.cipherText.Length; i = i + cipher.blockSize)
                {
                    byte[] tempBlock = new byte[cipher.blockSize];
                    for (int j = 0; j < cipher.blockSize; j++)
                    {
                        tempBlock[j] = cipher.cipherText[i + j];
                    }
                    cipherBlocks.Add(tempBlock);
                }

                List<byte[]> plainBlocks = new List<byte[]>();
                byte[] IV = cipher.IV;
                foreach (byte[] cipherBlock in cipherBlocks)
                {
                    byte[] decipheredBlock = ECBMode.decrypt(cipherBlock, cipher.key, IV);
                    byte[] plainBlock = Utils.XORByteArrayAgainstByteArray(decipheredBlock, IV);
                    plainBlocks.Add(plainBlock);
                    IV = cipherBlock;
                }

                int index = 0;
                foreach (byte[] b in plainBlocks)
                {
                    for (int i = 0; i < cipher.blockSize; i++)
                    {
                        plainText[index] = b[i];
                        index++;
                    }
                }

                cipher.plainText = plainText;
            }

            /// <summary>
            /// Encrypt the plain text
            /// </summary>
            /// <param name="plainText"></param>
            /// <returns></returns>
            public static void encrypt(BlockCipherdep cipher)
            {
                byte[] plainText = cipher.plainText;
                if ((plainText.Length % cipher.blockSize) != 0)
                    plainText = Utils.PKCSPadByteArrayToBlockSize(plainText, cipher.blockSize);

                List<byte[]> plainBlocks = new List<byte[]>();
                for (int i = 0; i < plainText.Length; i = i + cipher.blockSize)
                {
                    byte[] plainBlock = new byte[cipher.blockSize];
                    for (int j = 0; j < cipher.blockSize; j++)
                    {
                        plainBlock[j] = plainText[i + j];
                    }
                    plainBlocks.Add(plainBlock);
                }

                List<byte[]> encryptedBlocks = new List<byte[]>();
                byte[] IV = cipher.IV;
                foreach (byte[] plainBlock in plainBlocks)
                {
                    byte[] XORedBlock = Utils.XORByteArrayAgainstByteArray(plainBlock, IV);
                    byte[] encryptedBlock = ECBMode.encrypt(XORedBlock, cipher.key, IV);
                    encryptedBlocks.Add(encryptedBlock);
                    IV = encryptedBlock;
                }

                byte[] cipherText = new byte[encryptedBlocks.Count * cipher.blockSize];
                int index = 0;
                foreach (byte[] cipherBlock in encryptedBlocks)
                {
                    for (int i = 0; i < cipher.blockSize; i++)
                    {
                        cipherText[index] = cipherBlock[i];
                        index++;
                    }
                }

                cipher.cipherText = cipherText;
            }
        }
        /// <summary>
        /// Implementation of the ECB Mode Block cipher.
        /// </summary>
        public class ECBMode
        {
            public static byte[] encrypt(byte[] plainText, byte[] key)
            {
                byte[] iv = new byte[key.Length];
                for (int i = 0; i < iv.Length; i++)
                    iv[i] = 0x00;
                return encrypt(plainText, key, iv);
            }

            public static byte[] encrypt(byte[] plainText, byte[] key, byte[] iv)
            {
                var aes = new System.Security.Cryptography.AesManaged
                {
                    KeySize = 128,
                    Key = key,
                    BlockSize = 128,
                    Mode = System.Security.Cryptography.CipherMode.ECB,
                    Padding = System.Security.Cryptography.PaddingMode.Zeros,
                    IV = iv
                };

                var encrypted = aes.CreateEncryptor(aes.Key, aes.IV).TransformFinalBlock(plainText, 0, plainText.Length);
                return encrypted;
            }

            public static byte[] decrypt(byte[] cipherText, byte[] key)
            {
                byte[] iv = new byte[key.Length];
                for (int i = 0; i < iv.Length; i++)
                    iv[i] = 0x00;
                return decrypt(cipherText, key, iv);
            }

            public static byte[] decrypt(byte[] cipherText, byte[] key, byte[] iv)
            {
                var aes = new System.Security.Cryptography.AesManaged
                {
                    KeySize = 128,
                    Key = key,
                    BlockSize = 128,
                    Mode = System.Security.Cryptography.CipherMode.ECB,
                    Padding = System.Security.Cryptography.PaddingMode.Zeros,
                    IV = iv
                };

                var decrypted = aes.CreateDecryptor(aes.Key, aes.IV).TransformFinalBlock(cipherText, 0, cipherText.Length);
                return decrypted;
            }
        }


        /// <summary>
        /// Runs and decodes the challenge, just so so we have an easy interface for doing it
        /// </summary>
        /// <returns></returns>
        public static string doChallenge10()
        {
            string plainText = "";
            string key = "YELLOW SUBMARINE";

            BlockCipherdep cipher = new BlockCipherdep();            
            cipher.key = CryptoPalChallenges.Utils.ConvertStringToByteArray(key);
            cipher.blockSize = cipher.key.Length;            

            byte[] IV = new byte[16];
            for (int i = 0; i < IV.Length; i++)
                IV[i] = 0x00;
            cipher.IV = IV;

            string lines = File.ReadAllText(@"..\..\..\CryptoPalChallenges\Files\Set2Challenge10.txt");
            byte[] encryptedText = Convert.FromBase64String(lines);
            cipher.cipherText = encryptedText;

            BlockCipherdep.CBCMode.decrypt(cipher);
            plainText = Utils.ConvertByteArrayToString(cipher.plainText);

            return plainText;
        }

        /// <summary>
        /// The oracle for Challenge 11
        /// </summary>
        public static void doChallenge11()
        {
            byte[] input = Utils.ConvertStringToByteArray("abcdefghijklmnopqrstuvwyxz123456abcdefghijklmnopqrstuvwyxz123456abcdefghijklmnopqrstuvwyxz123456");

            byte[] cipherText = encryptRandomly(input);

            Console.WriteLine(isEBCMode(cipherText));
        }

        public static Random rnd;
        public static byte[] ChallengeKey; //{ get; set; }
        /// <summary>
        /// Challenge 12 requires a randomly generated key that stays the same during execution
        /// </summary>
        /// <param name="key"></param>
        /// The method here is quite primative, I didn't get it to work with blocks. Rather used the entire ciphertext as one
        /// TODO: Get this working on a block-by-block basis
        public static void doChallenge12()
        {
            //Create the original message and append the required string to it
            byte[] originalMessage = Utils.ConvertStringToByteArray("This is the original plaintext. Let's see what happens here.");
            ChallengeKey = generateRandomAESKey();

            //Now, encrypt this new plaintext using the oracle
            byte[] cipherText = challenge12Oracle(originalMessage);

            //Let's find the cipher length
            int blockSize = findBlockSize(ChallengeKey);

            //Let's check that we are using ECB
            bool isECB = isEBCMode(cipherText);

            //Build up the dictionary we need
            //Get the number of blocks used by the secret string
            byte[] nullCipher = challenge12Oracle(Utils.ConvertStringToByteArray(""));
            int blocksUsedBySecretString = nullCipher.Length;
            string retrievedString = "";
            StringBuilder decodedBlocks = new StringBuilder();
            //for (int j = 0; j < blocksUsedBySecretString; j++)
            {
                //Start the attack
                byte[] retrievedBytes = new byte[blocksUsedBySecretString];   //The bytes we have retrieved using the attack
                for (int i = 0; i < retrievedBytes.Length; i++)
                    retrievedBytes[i] = 0x41;
                
                for (int i = blocksUsedBySecretString - 1; i >= 0; i--)             //Iterate over each byte in the block
                {
                    //Take the received bytes and create a dictionary of all the next possible bytes
                    Dictionary<string, string> byteDictionary = buildByteDictionary(retrievedBytes.Take(blocksUsedBySecretString - 1).ToArray());
                    //We now take the retrieved bytes so far and feed it to the oracle
                    byte[] oracleInput = retrievedBytes.Take(i).ToArray();    //Take the first i amount of bytes
                    //firstByteCipher will now have it's last byte being the next unknown in the secret string in the block we have grabbed
                    string firstByteCipher = Utils.ConvertByteArrayToString(challenge12Oracle(oracleInput).Take(blocksUsedBySecretString).ToArray());
                    //Compare the block we returned from the encryption algorithm to the dictionary to find it's corresponding plaintext
                    if (byteDictionary.ContainsKey(firstByteCipher))
                        retrievedString = byteDictionary[firstByteCipher];
                    else
                        retrievedString = string.Format("{0}X", retrievedString);
                    byte retrievedByte = Utils.ConvertStringToByteArray(retrievedString)[blocksUsedBySecretString - 1];       //This is the new byte that we have "decoded"
                    retrievedBytes = updateRetrievedBytes(retrievedBytes, retrievedByte);
                }
                decodedBlocks.Append(retrievedString);
                Console.Write(retrievedString);
            }
        }

        public static void doChallenge13()
        {
            string cookie = "foo=bar&baz=qux&zap=zazzle";
            Dictionary<string, string> cookieDictionary = parseStructuredCookie(cookie);

            string emailAddress = "aname@bar.com";
            cookie = createCookieForProfile(emailAddress);
            cookieDictionary = parseStructuredCookie(cookie);

            byte[] key = generateRandomAESKey();    //The key would actually be part of the oracle, but we are going to use it here just for simplicities sake

            //using the ciphertext we get now, we want to escalate the role to admin
            byte[] cipherText = BlockCipherdep.ECBMode.encrypt(Utils.ConvertStringToByteArray(cookie), key);
            /*At this point, our cookie looks like this: email=foo@bar.com&uid=10&role=user
            Which is broken up by ECB into 16 bytes packets to be encoded:
            Packet 0:   email=aname@bar.                        
            Packet 1:   com&uid=10&role=                        
            Packet 2:   user
            This means that the role characteristic sits in Packet 2. If we can figure out the encoding of "admin", we can replace Packet 2 of the cipherText to get the escalation
            */

            //Let's create a cookie that will have "admin" at the start of a block. The only thing we can use is the createCookieForProfile, so we can actually only use the email address
            //We also want to pad the end, so that we get a block that we can use directly, without any issues
            byte[] emailBytes = Utils.PKCSPadByteArrayToBlockSize(Utils.ConvertStringToByteArray("admin"), 16); //This gives us the block that we want to encode
            //Now, to force this to be in the correct place when we create the cookie, we prepend 10 x's to the front of this
            StringBuilder sb = new StringBuilder("xxxxxxxxxx");
            sb.Append(Utils.ConvertByteArrayToString(emailBytes));
            emailBytes = Utils.ConvertStringToByteArray(sb.ToString());

            cookie = createCookieForProfile(sb.ToString());
            byte[] adminCipherText = BlockCipherdep.ECBMode.encrypt(Utils.ConvertStringToByteArray(cookie), key);
            //Now, the second block of the adminCipherText should contain the "admin" block, with padding of 11 afterwards

            //Convert the cipher text into a List so we can work with it easily
            List<byte[]> cipherList = Utils.ConvertByteArrayToList(cipherText, 16);
            //Convert the adminCipherText into a List so we can insert it into cipherText
            List<byte[]> adminCipherList = Utils.ConvertByteArrayToList(adminCipherText, 16);
            List<byte[]> newCipherList = new List<byte[]>(); //This will be where we store the new ciphertext that we think is going to have the admin role
            newCipherList.Add(cipherList[0]);   //The first block of the cipherText, which contains the "email=an...." bit
            newCipherList.Add(cipherList[1]);   //The second part that contains the bit that should end in "user="
            newCipherList.Add(adminCipherList[1]);     //The injected part that should contain the "admin...." part to get us the new role

            byte[] newCipherText = Utils.ConvertListToByteArray(newCipherList);
            byte[] decryptedCookieText = BlockCipherdep.ECBMode.decrypt(newCipherText, key);

            string decrpytedCookie = Utils.ConvertByteArrayToString(decryptedCookieText);
            cookieDictionary = parseStructuredCookie(decrpytedCookie);
            //This gives us exactly what we want. The only remaining issue is the padding on the "admin" part, but that can easily be removed
        }

        public static void doChallenge14()
        {
            rnd = new Random();
            ChallengeKey = generateRandomAESKey();

            string input = "This is the string that is controlled by the attacker";
            byte[] attackerInput = Utils.ConvertStringToByteArray(input);

            byte[] cipherText = challenge14Oracle(attackerInput);

            //int blockSize = 16;     //TODO: Should find from cipherText
            //bool isECB = true;      //TODO: Should also find from cipherText

            //TODO: complete challenge. have run out of time for this.
        }

        public static void doChallenge16()
        {
            rnd = new Random();
            ChallengeKey = generateRandomAESKey();

            //string input = "Ice Ice Baby";
            string input = ";admin=true;;;;;";
            BlockCipherdep cipher;
            byte[] cipherText = challenge16Oracle(input, out cipher);

            //test first to make sure that this string returns a false
            Console.WriteLine("Known string returns {0}", challenge16Decrypter(cipher));

            //now, we move on to trying to break the ciphertext. at this point, all we have is the ciphertext
            //we know that in cbc, a 1-bit error in a cipherblock will scramble the current block and the next block. this will cause the same error in both blocks
            //just out of interest, in ecb a 1-bit error will only mess with the current block

        }

        public static byte[] challenge16Oracle(string input, out BlockCipherdep cipher)
        {
            string prepend = "comment1=cooking%20MCs;userdata=";
            string append = ";comment2=%20like%20a%20pound%20of%20bacon";
            string plainText = prepend + input + append;
            //drop special chars
            plainText = plainText.Replace(";", "");
            plainText = plainText.Replace("=", "");

            cipher = new BlockCipherdep();
            cipher.blockSize = 16;
            byte[] iv = new byte[16];
            for (int i = 0; i < iv.Length; i++)
                iv[i] = 0x00;
            cipher.IV = iv;
            cipher.key = ChallengeKey;
            byte[] plainTextBytes = Utils.ConvertStringToByteArray(plainText);
            cipher.plainText = plainTextBytes;

            BlockCipherdep.CBCMode.encrypt(cipher);
            return cipher.cipherText;
        }

        public static bool challenge16Decrypter(BlockCipherdep cipher)
        {
            BlockCipherdep.CBCMode.decrypt(cipher);
            byte[] plainText = cipher.plainText;

            string plain = Utils.ConvertByteArrayToString(plainText);

            if (plain.Contains("admin=true"))
                return true;
            return false;
        }

        /// <summary>
        /// Creates the cookie for Challenge 13 from the given email address. Will eat & and = characters
        /// </summary>
        /// <param name="emailAddress"></param>
        /// <returns></returns>
        public static string createCookieForProfile(string emailAddress)
        {
            emailAddress = emailAddress.Replace("&", string.Empty);
            emailAddress = emailAddress.Replace("=", string.Empty);
            return string.Format("email={0}&uid=10&role=user", emailAddress);
        }

        /// <summary>
        /// Parse the given cookie for Challenge 13
        /// </summary>
        /// <param name="cookie"></param>
        /// <returns></returns>
        public static Dictionary<string, string> parseStructuredCookie(string cookie)
        {
            Dictionary<string, string> cookieDictionary = new Dictionary<string, string>();
            string[] lines = cookie.Split('&');
            foreach (string line in lines)
            {
                string[] data = line.Split('=');
                cookieDictionary.Add(data[0], data[1]);
            }
            return cookieDictionary;
        }
        
        /// <summary>
        /// The Dictionary creator for the ECB byte-by-byte attack
        /// </summary>
        /// <param name="retrievedBytes"></param>
        /// <returns></returns>
        public static Dictionary<string, string> buildByteDictionary(byte[] retrievedBytes)
        {
            Dictionary<string, string> byteDictionary = new Dictionary<string, string>();
            byte[] byteBuilder = new byte[retrievedBytes.Length + 1];
            retrievedBytes.CopyTo(byteBuilder, 0);
            for (byte i = 0x00; i <= 0x7E; i++)
            {
                byteBuilder[retrievedBytes.Length] = i;
                byte[] byteCipher = challenge12Oracle(byteBuilder).Take(retrievedBytes.Length + 1).ToArray();
                byteDictionary.Add(Utils.ConvertByteArrayToString(byteCipher), Utils.ConvertByteArrayToString(byteBuilder));
            }

            return byteDictionary;
        }

        /// <summary>
        /// Used by the ECB byte-by-byte attack, add the new decoded byte to the array
        /// </summary>
        /// <param name="retrievedBytes"></param>
        /// <param name="newByte"></param>
        /// <returns></returns>
        private static byte[] updateRetrievedBytes(byte[] retrievedBytes, byte newByte)
        {
            //take our current byte[], drop the first byte and append the new byte into its place
            byte[] newByteArray = new byte[retrievedBytes.Length];
            newByteArray[retrievedBytes.Length - 2] = newByte;
            for (int i = (newByteArray.Length - 3); i >= 0; i--)
                newByteArray[i] = retrievedBytes[i + 1];
            return newByteArray;
        }

        /// <summary>
        /// This represents an unknown encryption function that we want to figure out. In this case, it adds some string to a known message
        /// </summary>
        /// <param name="originalMessage"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] challenge12Oracle(byte[] originalMessage)
        {
            string lines = File.ReadAllText(@"..\..\..\CryptoPalChallenges\Files\Set2Challenge12.txt");
            byte[] toBeAppended = Convert.FromBase64String(lines);
            byte[] plainText = new byte[originalMessage.Length + toBeAppended.Length];
            originalMessage.CopyTo(plainText, 0);
            toBeAppended.CopyTo(plainText, originalMessage.Length);

            return BlockCipherdep.ECBMode.encrypt(plainText, ChallengeKey);
        }

        /// <summary>
        /// The oracle for Challenge 14. Should return AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key).
        /// attacker-controlled is the part we inject, referenced here as originalMessage
        /// </summary>
        /// <param name="originalMessage"></param>
        /// <returns></returns>
        public static byte[] challenge14Oracle(byte[] originalMessage)
        {
            int numOfBytesToBePrepended = rnd.Next(10, 100);    //number here are selected by me
            List<byte> plainText = new List<byte>();
            for (int i = 0; i < numOfBytesToBePrepended; i++)   //start with the randomly generated plainText
                plainText.Add((byte)rnd.Next(byte.MinValue, byte.MaxValue));
            for (int i = 0; i < originalMessage.Length; i++)    //add in the attacker-controlled part
                plainText.Add(originalMessage[i]);
            string target = "This is the added bit from the oracle. With a bit of luck, we should be able to find this without a problem.";
            byte[] targetBytes = Utils.ConvertStringToByteArray(target);
            for (int i = 0; i < targetBytes.Length; i++)        //add in the target-bytes, which is what we want to figure out
                plainText.Add(targetBytes[i]);

            byte[] output = new byte[plainText.Count];
            for (int i = 0; i < output.Length; i++)             //convert the list into a byte[] so it can be encrypted
                output[i] = plainText[i];

            return BlockCipherdep.ECBMode.encrypt(output, ChallengeKey);
        }

        /// <summary>
        /// Find the required block size of the ciphertext for the given key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static int findBlockSize(byte[] key)
        {
            int suspectedBlockSize = 0;
            int confirmedBlockSize = 0;
            bool foundSuspect = false;

            StringBuilder sb = new StringBuilder();
            sb.Append("A");
            for (int i = 1; i < (256 / 8); i++)
            {
                int currentPlainLength = sb.ToString().Length;
                byte[] cipherText = BlockCipherdep.ECBMode.encrypt(Utils.ConvertStringToByteArray(sb.ToString()), key);
                int currentCipherLength = cipherText.Length;
                if (!(foundSuspect) && (currentCipherLength > suspectedBlockSize))
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

        /// <summary>
        /// Generate a random AES key of 16 byte (128-bit) length
        /// </summary>
        /// <returns></returns>
        public static byte[] generateRandomAESKey()
        {
            Random rnd = new Random();
            byte[] key = new byte[16];
            for (int i = 0; i < key.Length; i++)
                key[i] = (byte)(rnd.Next(byte.MinValue, byte.MaxValue));
            return key;
        }

        /// <summary>
        /// Encrpyt under a randomly chosen ECB or CBC algorithm, with appending and random IVs if necessary
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static byte[] encryptRandomly(byte[] input)
        {
            Random rnd = new Random();

            //Insert random bytes at the beginning and end
            byte[] inputWithRandom = appendRandomBytes(input);

            int choice = rnd.Next(0, 2);
            byte[] cipherText;
            if (choice == 0)    //encrypt under ECB
            {
                cipherText = ECBMode.encrypt(inputWithRandom, generateRandomAESKey());
            }
            else
            {
                BlockCipherdep cipher = new BlockCipherdep();
                cipher.plainText = inputWithRandom;
                cipher.key = generateRandomAESKey();
                cipher.blockSize = cipher.key.Length;
                cipher.IV = generateRandomIV();

                CBCMode.encrypt(cipher);
                cipherText = cipher.cipherText;
            }

            return cipherText;
        }

        /// <summary>
        /// Detects if the given cipherText is ECB mode encrypted
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static bool isEBCMode(byte[] input)
        {
            List<byte[]> cipherBlocks = new List<byte[]>();
            for (int i = 0; i < input.Length; i = i + 16)
            {
                byte[] cipherBlock = new byte[16];
                for (int j = 0; j < 16; j++)
                    cipherBlock[j] = input[i + j];
                cipherBlocks.Add(cipherBlock);
            }

            List<byte[]> uniques = new List<byte[]>();
            foreach (byte[] cipherBlock in cipherBlocks)
            {
                foreach (byte[] compare in uniques)
                {
                    if (Enumerable.SequenceEqual(cipherBlock, compare))
                        return true;
                }
                uniques.Add(cipherBlock);
            }

            return false;
        }

        

        private static byte[] appendRandomBytes(byte[] input)
        {
            Random rnd = new Random();
            int numberToBePrepended = rnd.Next(5, 10);
            int numberToBeAppended = rnd.Next(5, 10);

            byte[] output = new byte[numberToBePrepended + input.Length + numberToBeAppended];
            for (int i = 0; i < numberToBePrepended; i++)
                output[i] = (byte)(rnd.Next(byte.MinValue, byte.MaxValue));
            for (int i = numberToBePrepended; i < (numberToBePrepended + input.Length); i++)
                output[i] = input[i - numberToBePrepended];
            for (int i = (numberToBePrepended + input.Length); i < (numberToBePrepended + input.Length + numberToBeAppended); i++)
                output[i] = (byte)(rnd.Next(byte.MinValue, byte.MaxValue));

            return output;
        }

        private static byte[] generateRandomIV()
        {
            Random rnd = new Random();
            byte[] iv = new byte[16];
            for (int i = 0; i < iv.Length; i++)
                iv[i] = (byte)(rnd.Next(byte.MinValue, byte.MaxValue));
            return iv;
        }
    }

    public partial class Utils
    {
        public static byte[] ConvertListToByteArray(List<byte[]> input)
        {
            byte[] output = new byte[input.Count * input[0].Length];
            for (int i = 0; i < input.Count; i++)
            {
                for (int j = 0; j < input[0].Length; j++)
                {
                    output[(i * input[0].Length) + j] = input[i][j];
                }
            }
            return output;
        }

        /// <summary>
        /// Send in a byte[] and the blockSize, get a list of the array broken up into blocks
        /// </summary>
        /// <param name="input"></param>
        /// <param name="blockSize"></param>
        /// <returns></returns>
        public static List<byte[]> ConvertByteArrayToList(byte[] input, int blockSize)
        {
            List<byte[]> output = new List<byte[]>();
            byte[] array = new byte[blockSize];

            for (int i = 0; i < input.Length; i = i + blockSize)
            {
                array = input.Skip(i).Take(blockSize).ToArray();
                output.Add(array);
            }

            return output;
        }

        /// <summary>
        /// Using PKCS#7 padding, pad the input string to the required blocksize. Send in a string, get back a string with padding and new length
        /// </summary>
        /// <param name="_input"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public static string PKCSPadStringToBlockSize(string _input, int blockSize)
        {
            int paddingLength = 0;
            if (_input.Length == blockSize)
                return _input.PadRight((_input.Length + 1), (char)(-_input.Length));

            string inputToBePadded = _input;
            while (inputToBePadded.Length > blockSize)   //If the string is longer than the length, we only want to pad the last block
            {
                inputToBePadded = inputToBePadded.Substring(blockSize, (inputToBePadded.Length - blockSize));
            }
            paddingLength = blockSize - inputToBePadded.Length;
            return inputToBePadded.PadRight(blockSize, (char)paddingLength);          
        }

        /// <summary>
        /// Using PKCS#7 padding, pad the input to the required block size. Uses byte arrays
        /// </summary>
        /// <param name="_input"></param>
        /// <param name="blockSize"></param>
        /// <returns></returns>
        public static byte[] PKCSPadByteArrayToBlockSize(byte[] _input, int blockSize)
        {
            string input = Utils.ConvertByteArrayToString(_input);
            int unpaddedLength = input.Length / blockSize;
            int paddingLength = input.Length % blockSize;
            input = input.PadRight((unpaddedLength + 1) * blockSize, (char)(16 - paddingLength));
            return Utils.ConvertStringToByteArray(input);
        }

        /// <summary>
        /// XORs two byte arrays against eachother and returns a byte[]
        /// </summary>
        /// <param name="_input1"></param>
        /// <param name="_input2"></param>
        /// <returns></returns>
        public static byte[] XORByteArrayAgainstByteArray(byte[] _input1, byte[] _input2)
        {
            byte[] output = new byte[_input1.Length];
            for (int i = 0; i < output.Length; i++)
                output[i] = (byte)(_input1[i] ^ _input2[i]);

            return output;
        }

        /// <summary>
        /// Check if input has valid PKCS#7 padding in it. 
        /// Throws InvalidPadding Exception if not, returns stripped input if it is valid
        /// </summary>
        /// <param name="input"></param>
        /// <param name="valid"></param>
        /// <returns></returns>
        public static byte[] isValidPadding(byte[] input, out bool valid)
        {
            valid = false;
            byte[] output = new byte[0];

            //first, let's make sure our length is correct. We know it should be a minimum of 16 byte (128-bit)
            if (input.Length % 16 != 0)
                throw new InvalidPaddingException("Incorrect message length");

            //now, we have an indication of the block size, so we should be able to look at the last byte and see how many bytes of padding we might have here
            byte paddingLength = input[input.Length - 1];
            //we want to make sure all padding bytes are the same
            byte[] paddingBytes = input.Skip(input.Length - paddingLength).Take(paddingLength).ToArray();
            for (int i = 0; i < paddingBytes.Length; i++)
            {
                if (paddingBytes[i] != paddingLength)
                    throw new InvalidPaddingException(string.Format("Padding bytes are not the same {0} compared to {1}", paddingBytes[i], paddingLength));
            }

            //check if we have the correct amount of bytes as the padding number indicats
            int bytesCounted = 0;
            for (int i = input.Length - 1; i >=0; i--)
            {
                if (bytesCounted == paddingLength)
                    break;
                if (input[i] == paddingLength)
                    bytesCounted++;
                else
                    throw new InvalidPaddingException(string.Format("Padding bytes count and actual are different {0} indicates {1} actual", paddingLength, bytesCounted));
            }
           
            
            //we can simply extract only the part of the byte array that is not padded and return this
            
            valid = true;
            return input.Skip(0).Take(input.Length - paddingLength).ToArray();
        }
    }
}
