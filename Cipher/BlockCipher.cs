using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Extensions;

namespace Cipher
{
    public abstract class BlockCipher
    {
        private byte[] _key;
        /// <summary>
        /// The BlockCipher-compliant key. Will check and throw IncorrectKeySizeException if not valid key length
        /// </summary>        
        public byte[] key
        {
            get
            {
                return this._key;
            }
            set
            {
                if (value.Length == blockSize)
                    this._key = value;
                else
                    throw new IncorrectKeySizeException(string.Format("Key is {0}, BlockSize is {1}", _key.Length, blockSize));
            } 
        }
        /// <summary>
        /// The CipherText component. Can be set and used to generate the plaintext or get when plaintext has been encrypted.
        /// </summary>
        public byte[] cipherText { get; set; }
        /// <summary>
        /// The PlainText component. Can be set and use to generate the ciphertext or get when ciphertext has been decrypted.
        /// </summary>
        public byte[] plainText { get; set; }

        private int _blockSize;
        /// <summary>
        /// The BlockSize for the the key. Should be the same size as the key. Default is 16 bytes (128-bit).
        /// Set in bytes.
        /// </summary>
        public int blockSize
        {
            get
            {
                return this._blockSize;
            }
            set
            {
                if ((value % 8) == 0)
                    this._blockSize = value;
                else
                    throw new InvalidBlockSizeException(string.Format("Invalid block size, must be multiple of 8, size is {0}", blockSize));
            }
        }

        private byte[] _IV;
        /// <summary>
        /// The initial vector for CBC Mode. Must be same length as blockSize
        /// </summary>
        public byte[] IV
        {
            get
            {
                return this._IV;
            }
            set
            {
                if (value.Length == blockSize)
                    this._IV = value;
                else if (this.GetType() == typeof(CTRMode))
                {
                    if (value.Length == blockSize / 2)
                        this._IV = value;
                    else
                        throw new InvalidLengthNonce();
                }                        
                else
                    throw new InvalidLengthIV();
            }
        }

        /// <summary>
        /// Padding to be used. 
        /// </summary>
        public System.Security.Cryptography.PaddingMode padding { get; set; } = System.Security.Cryptography.PaddingMode.Zeros;
        
        /// <summary>
        /// Encrpyt the set plainText using the set key. Will write cipherText property, which can be getted.
        /// </summary>
        /// <returns></returns>
        abstract public void encrypt();
        /// <summary>
        /// Decrypt the set cipherText using the set key. Will write plainText property, which can be getted.
        /// </summary>
        /// <returns></returns>
        abstract public void decrypt();

        /// <summary>
        /// Pad the given string to blockSize, returns a string
        /// </summary>
        /// <param name="_input"></param>
        /// <returns></returns>
        public string PCKS7Padding(string input)
        {
            //Work for Set 2, Challenge 9
            int paddingBytes = this.blockSize - (input.Length % this.blockSize);

            if (paddingBytes == 0)   //already the correct blockSize
                return input.PadRight(input.Length + this.blockSize, (char)this.blockSize);

            return input.PadRight(input.Length + paddingBytes, (char)paddingBytes);
        }

        public byte[] PCKS7Padding(byte[] input)
        {
            string inputString = input.toString();
            return this.PCKS7Padding(inputString).toByteArray();
        }

        /// <summary>
        /// Checks if the given cipherText is in ECB Mode
        /// </summary>
        /// <returns></returns>
        public bool isECBMode()
        {
            bool isECB = false;
            List<byte[]> cipherBlocks = cipherText.toList(16); //turn cipherText in List of byte[], where each byte[] represents one ECB block
            List<byte[]> uniqueBlocks = new List<byte[]>();  //The list to be populated with each unique block
            foreach (byte[] block in cipherBlocks)
            {
                bool found = false;
                foreach (byte[] compare in uniqueBlocks)
                {
                    if (Enumerable.SequenceEqual(block, compare))
                        found = true;   //We found this block in uniqueBlocks, so we have found a duplicate
                }
                if (!found)
                    uniqueBlocks.Add(block); //We haven't got this block already, so it is a new unique block
            }

            if (cipherBlocks.Count != uniqueBlocks.Count)
                return true;
            return isECB;
        }

        /// <summary>
        /// Calculates the blocksize of the BlockCipher object
        /// </summary>
        /// <returns></returns>
        public int findBlockSize()
        {
            int suspectedBlockSize = 0;
            int confirmedBlockSize = 0;
            bool foundSuspect = false;

            //Let's call the oracle with an ever-increasing string until the ciphertext gets longer. 
            StringBuilder sb = new StringBuilder("A");
            for (int i = 1; i < (256 / 8); i++)
            {
                int currentPlainLength = sb.ToString().Length;
                BlockCipher ecb = new BlockCipher.ECBMode();
                ecb.plainText = sb.ToString().toByteArray();
                byte[] ecbKey = new byte[this.blockSize];
                for (byte j = 0; j < ecbKey.Length; j++)
                    ecbKey[j] = j;
                ecb.blockSize = this.blockSize;
                ecb.key = ecbKey;
                ecb.encrypt();
                int currentCipherLength = ecb.cipherText.Length;
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

        private void removePadding()
        {
            int paddingCount = 0;
            for (int i = this.plainText.Length - 1; i > 0; i--)
            {
                if (this.plainText[i] == '\0')
                    paddingCount++;
            }

            byte[] output = new byte[this.plainText.Length - paddingCount];
            for (int i = 0; i < output.Length; i++)
                output[i] = this.plainText[i];

            this.plainText = output;
        }

        private void removePCKSPadding()
        {
            byte paddingLength = this.plainText[this.plainText.Length - 1];
            byte[] output = new byte[this.plainText.Length - paddingLength];
            for (int i = 0; i < output.Length; i++)
                output[i] = this.plainText[i];
            this.plainText = output;
        }

        /// <summary>
        /// Check if input has valid PKCS#7 padding in it. 
        /// Throws InvalidPadding Exception if not, returns stripped input if it is valid
        /// </summary>
        /// <param name="input"></param>
        /// <param name="valid"></param>
        /// <returns></returns>
        public byte[] isValidPadding(out bool valid)
        {
            valid = false;
            byte[] output = new byte[0];

            //first, let's make sure our length is correct. We know it should be a minimum of 16 byte (128-bit)
            if (this.plainText.Length % 16 != 0)
                throw new InvalidPaddingException("Incorrect message length");

            //now, we have an indication of the block size, so we should be able to look at the last byte and see how many bytes of padding we might have here
            byte paddingLength = this.plainText[this.plainText.Length - 1];
            //we want to make sure all padding bytes are the same
            byte[] paddingBytes = this.plainText.Skip(this.plainText.Length - paddingLength).Take(paddingLength).ToArray();
            for (int i = 0; i < paddingBytes.Length; i++)
            {
                if (paddingBytes[i] != paddingLength)
                    throw new InvalidPaddingException(string.Format("Padding bytes are not the same {0} compared to {1}", paddingBytes[i], paddingLength));
            }

            //check if we have the correct amount of bytes as the padding number indicats
            int bytesCounted = 0;
            for (int i = this.plainText.Length - 1; i >= 0; i--)
            {
                if (bytesCounted == paddingLength)
                    break;
                if (this.plainText[i] == paddingLength)
                    bytesCounted++;
                else
                    throw new InvalidPaddingException(string.Format("Padding bytes count and actual are different {0} indicates {1} actual", paddingLength, bytesCounted));
            }


            //we can simply extract only the part of the byte array that is not padded and return this

            valid = true;
            return this.plainText.Skip(0).Take(this.plainText.Length - paddingLength).ToArray();
        }

        /// <summary>
        /// Electronic Code Book implementation. Default constructor sets blockSize of 16 bytes (128-bit)
        /// </summary>
        public class ECBMode : BlockCipher
        {   
            /// <summary>
            /// Default constructor, uses blockSize of 16 bytes (128-bit)
            /// </summary>
            public ECBMode()
            {
                blockSize = 16;
            }
                     
            public override void encrypt()
            {
                if (this.plainText == null)
                    throw new PlainTextException();
                byte[] iv = new byte[this.key.Length];
                for (int i = 0; i < iv.Length; i++)
                    iv[i] = 0x00;
                var aes = new System.Security.Cryptography.AesManaged
                {
                    KeySize = this.key.Length * 8,
                    Key = this.key,
                    BlockSize = this.blockSize * 8,
                    Mode = System.Security.Cryptography.CipherMode.ECB,
                    Padding = this.padding,
                    IV = iv
                };

                this.cipherText = aes.CreateEncryptor(aes.Key, aes.IV).TransformFinalBlock(this.plainText, 0, this.plainText.Length);
            }

            public override void decrypt()
            {
                if (this.cipherText == null)
                    throw new CipherTextException();
                byte[] iv = new byte[this.key.Length];
                for (int i = 0; i < iv.Length; i++)
                    iv[i] = 0x00;
                var aes = new System.Security.Cryptography.AesManaged
                {
                    KeySize = this.key.Length * 8,
                    Key = this.key,
                    BlockSize = this.blockSize * 8,
                    Mode = System.Security.Cryptography.CipherMode.ECB,
                    Padding = this.padding,
                    IV = iv
                };

                this.plainText = aes.CreateDecryptor(aes.Key, aes.IV).TransformFinalBlock(this.cipherText, 0, this.cipherText.Length);
            }
        }

        public class CBCMode : BlockCipher
        {
            /// <summary>
            /// Default constructor, uses blockSize of 16 bytes (128-bit), IV of 0x00s
            /// </summary>
            public CBCMode()
            {
                this.blockSize = 16;
                byte[] iv = new byte[this.blockSize];
                for (int i = 0; i < iv.Length; i++)
                    iv[0] = 0x00;
                this.IV = iv;
            }

            public override void encrypt()
            {
                //check for padding and add if we need
                byte[] plain = this.plainText;
                if ((plain.Length % this.blockSize) != 0)
                    plain = this.PCKS7Padding(plain);

                //break the plainText into blockSize blocks to work with
                List<byte[]> plainBlocks = plain.toList(this.blockSize);

                //do the CBC encryption algorithm
                List<byte[]> cipherBlocks = new List<byte[]>();
                byte[] iv = this.IV;    //we are going to modify this, so extract it from the object
                BlockCipher ecb = new BlockCipher.ECBMode();    //CBC uses ECB as the basis for encryption
                ecb.key = this.key;
                foreach (byte[] plainBlock in plainBlocks)
                {
                    byte[] XORedBlock = Utilities.XORByteArrays(plainBlock, iv);                    
                    ecb.plainText = XORedBlock;
                    ecb.encrypt();
                    cipherBlocks.Add(ecb.cipherText);
                    iv = ecb.cipherText;    //update iv as the seed for the next block
                }

                this.cipherText = cipherBlocks.toByteArray();
            }

            public override void decrypt()
            {
                //get the cipherText blocks
                List<byte[]> cipherBlocks = this.cipherText.toList(this.blockSize);

                //do the CBC decryption algorithm
                List<byte[]> plainBlocks = new List<byte[]>();
                byte[] iv = this.IV;
                BlockCipher ecb = new BlockCipher.ECBMode();
                ecb.key = this.key;
                foreach (byte[] cipherBlock in cipherBlocks)
                {
                    ecb.cipherText = cipherBlock;
                    ecb.decrypt();
                    byte[] decypheredBlock = ecb.plainText;
                    byte[] plainBlock = Utilities.XORByteArrays(decypheredBlock, iv);
                    plainBlocks.Add(plainBlock);
                    iv = cipherBlock;
                }

                this.plainText = plainBlocks.toByteArray();
            }
        }

        public class CTRMode : BlockCipher
        {
            /// <summary>
            /// Default constructor, uses blockSize of 16 bytes (128-bit), IV (nonce) of 0 and counter of zero. Nonce and counter are little-endian
            /// </summary>
            public CTRMode()
            {
                this.blockSize = 16;
                byte[] nonce = new byte[this.blockSize / 2];
                for (int i = 0; i < nonce.Length; i++)
                    nonce[0] = 0x00;
                //nonce goes in top half of IV array
                byte[] counter = new byte[nonce.Length];
                for (int i = 0; i < counter.Length; i++)
                    counter[i] = 0x00;
                //counter goes in bottom half of nonce
                updateNonce(nonce, counter);                
            }

            public override void encrypt()
            {
                throw new NotImplementedException();
            }

            public override void decrypt()
            {
                
            }

            private void incrementCounter()
            {
                //seperate IV into nonce and counter
                byte[] nonce = new byte[this.IV.Length / 2];
                byte[] counter = new byte[this.IV.Length / 2];

                //copy IV into each appropriate array
                for (int i = 0; i < this.IV.Length; i++)
                {
                    if (i < nonce.Length)
                        nonce[i] = this.IV[i];
                    else
                        counter[i - (blockSize / 2)] = this.IV[i];
                }

                //increment counter
                for (int i = 0; i < counter.Length; i++)
                {
                    if (counter[i] < byte.MaxValue)
                    {
                        counter[i]++;
                        break;
                    }
                }

                //reassemble IV from nonce and counter
                this.updateNonce(nonce, counter);
            }

            private void updateNonce(byte[] nonce, byte[] counter)
            {
                byte[] IV = new byte[nonce.Length + counter.Length];
                for (int i = 0; i < IV.Length; i++)
                {
                    if (i < nonce.Length)
                        IV[i] = nonce[i];
                    else
                        IV[i] = counter[i - (blockSize / 2)];
                }
                this.IV = IV;
            }
        }
    }
}
