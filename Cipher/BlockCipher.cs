using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CryptoPalChallenges;

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
        public string PCKS7Padding(string _input)
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
        /// Pad the given byte[] to blockSize, returns the padded byte[]
        /// </summary>
        /// <param name="_input"></param>
        /// <returns></returns>
        public byte[] PCKS7Padding(byte[] _input)
        {
            string input = Utils.ConvertByteArrayToString(_input);
            int unpaddedLength = input.Length / blockSize;
            int paddingLength = input.Length % blockSize;
            input = input.PadRight((unpaddedLength + 1) * blockSize, (char)(16 - paddingLength));
            return Utils.ConvertStringToByteArray(input);
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
                    Padding = System.Security.Cryptography.PaddingMode.Zeros,
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
                    Padding = System.Security.Cryptography.PaddingMode.Zeros,
                    IV = iv
                };

                this.plainText = aes.CreateDecryptor(aes.Key, aes.IV).TransformFinalBlock(this.cipherText, 0, this.cipherText.Length);
                this.removePadding();
            }
        }

        public class CBCMode : BlockCipher
        {
            public byte[] IV { get; set; }

            public override void encrypt()
            {
                
            }

            public override void decrypt()
            {
                
            }
        }
    }
}
