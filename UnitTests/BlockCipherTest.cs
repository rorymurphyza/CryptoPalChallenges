using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cipher;
using Extensions;

namespace UnitTests
{
    [TestClass]
    public class BlockCipherTest
    {
        [TestMethod]
        public void ECBModeDefaultConstructorTest()
        {
            BlockCipher cipher = new BlockCipher.ECBMode();
            Assert.AreEqual(16, cipher.blockSize);
        }

        [TestMethod]
        public void BlockCipherBlockSizeTest()
        {
            BlockCipher cipher = new BlockCipher.ECBMode();
            cipher.blockSize = 8;
            Assert.AreEqual(8, cipher.blockSize);

            //try invalid block size
            try
            {
                cipher.blockSize = 12;
                Assert.Fail("This is an invalid blockSize");
            }
            catch (InvalidBlockSizeException e)
            {
                Assert.IsNotNull(e.Message);
            }
            catch (Exception e)
            {
                Assert.Fail(e.Message);
            }
        }

        [TestMethod]
        public void BlockCipherKeyTest()
        {
            BlockCipher cipher = new BlockCipher.ECBMode();
            ///check for case of valid key
            string key = "YELLOW SUBMARINE";
            cipher.key = key.toByteArray();
            Assert.AreEqual(key.Length, cipher.key.Length);
            Assert.AreEqual(key, cipher.key.toString());

            //check for short key size
            key = "YELLOW";
            try
            {
                cipher.key = key.toByteArray();
                Assert.Fail("Key size is incorrect");
            }
            catch (IncorrectKeySizeException e)
            {
                Assert.IsNotNull(e.Message);
            }
            catch (Exception e)
            {
                Assert.Fail(e.Message);
            }

            //check for long key size
            key = "YELLOWISH SUBMARINE";
            try
            {
                cipher.key = key.toByteArray();
                Assert.Fail("Key size is incorrect");
            }
            catch (IncorrectKeySizeException e)
            {
                Assert.IsNotNull(e.Message);
            }
            catch (Exception e)
            {
                Assert.Fail(e.Message);
            }

            //change blockSize and make sure we still work
            try
            {
                cipher.blockSize = 8;
                cipher.key = "YELLOWOW".toByteArray();
                Assert.AreEqual(8, cipher.blockSize);
                Assert.AreEqual("YELLOWOW", cipher.key.toString());
                Assert.AreEqual(cipher.blockSize, cipher.key.Length);
            }         
            catch (Exception e)
            {
                Assert.Fail(e.Message);
            }
        }

        [TestMethod]
        public void BlockCipherPCKS7PaddingTest()
        {
            BlockCipher cipher = new BlockCipher.ECBMode();
            cipher.blockSize = 8;
            string input = "YELLOW";
            string output = cipher.PCKS7Padding(input);
            string answer = "YELLOW\u0002\u0002";
            Assert.AreEqual(answer, output);
            Assert.AreEqual(cipher.blockSize, output.Length);

            cipher = new BlockCipher.ECBMode();
            input = "YELLOW SUBMAR";
            output = cipher.PCKS7Padding(input);
            answer = "YELLOW SUBMAR\u0003\u0003\u0003";
            Assert.AreEqual(answer, output);
            Assert.AreEqual(cipher.blockSize, output.Length);

            cipher = new BlockCipher.ECBMode();
            input = "YELLOW SUBMARINES ARE YELLOW";
            output = cipher.PCKS7Padding(input);
            answer = "YELLOW SUBMARINES ARE YELLOW\u0004\u0004\u0004\u0004";
            Assert.AreEqual(answer, output);
            Assert.AreEqual(0, output.Length % cipher.blockSize);

            cipher = new BlockCipher.ECBMode();
            input = "YELLOW SUBMARINE";
            output = cipher.PCKS7Padding(input);
            answer = "YELLOW SUBMARINE\u0010\u0010\u0010\u0010\u0010\u0010\u0010\u0010\u0010\u0010\u0010\u0010\u0010\u0010\u0010\u0010";
            Assert.AreEqual(answer, output);
            Assert.AreEqual(0, output.Length % cipher.blockSize);
        }

        [TestMethod]
        public void ECBEncryptionTest()
        {
            BlockCipher cipher = new BlockCipher.ECBMode();
            cipher.key = "YELLOW SUBMARINE".toByteArray();
            cipher.plainText = "ABCDEABCDEABCDEF".toByteArray();
            cipher.encrypt();

            string answer64 = "qtdEJb/T+P8idy91vnRt+A==";
            string answerHex = "aad74425bfd3f8ff22772f75be746df8";

            Assert.AreEqual(answer64, cipher.cipherText.toBase64String());
            Assert.AreEqual(answerHex, cipher.cipherText.toHexString());
        }

        [TestMethod]
        public void ECBDecryptionTest()
        {
            BlockCipher cipher = new BlockCipher.ECBMode();
            cipher.key = "YELLOW SUBMARINE".toByteArray();
            string input64 = "FYtzWIwGx67LrZRSLYdiOg==";
            cipher.cipherText = input64.base64ToByteArray();
            cipher.decrypt();

            string answer = "ABCDE";

            Assert.AreEqual(answer, cipher.plainText.toString());
        }

        [TestMethod]
        public void BlockCipherIVTest()
        {
            BlockCipher cipher = new BlockCipher.CBCMode();
            //check for case of valid IV
            byte[] iv = new byte[cipher.blockSize];
            for (int i = 0; i < iv.Length; i++)
                iv[i] = 0x00;
            cipher.IV = iv;
            Assert.AreEqual(cipher.blockSize, cipher.IV.Length);
            int ivSum = 0;
            foreach (byte b in cipher.IV)
                ivSum += b;
            Assert.AreEqual(0, ivSum);
            
            //check for short IV size
            string ivString = "YELLOW";            
            try
            {
                cipher.IV = ivString.toByteArray();
                Assert.Fail("IV size is incorrect at set");
            }
            catch (InvalidLengthIV e)
            {
                Assert.IsNotNull(e.Message);
            }
            catch (Exception e)
            {
                Assert.Fail(e.Message);
            }
        }

        [TestMethod]
        public void CBCModeDefaultConstructorTest()
        {
            BlockCipher cipher = new BlockCipher.CBCMode();
            Assert.AreEqual(16, cipher.blockSize);
            Assert.AreEqual(16, cipher.IV.Length);

            int ivSum = 0;
            for (int i = 0; i < cipher.IV.Length; i++)
                ivSum += cipher.IV[i];
            Assert.AreEqual(0, ivSum);
        }

        [TestMethod]
        public void CBCEncryptionTest()
        {
            string input = "ABCDEABCDEABCDEF";
            string key = "YELLOW SUBMARINE";

            BlockCipher cipher = new BlockCipher.CBCMode();
            cipher.blockSize = key.Length;
            cipher.key = key.toByteArray();
            byte[] iv = new byte[key.Length];
            for (int i = 0; i < iv.Length; i++)
                iv[i] = 0x00;
            cipher.IV = iv;
            cipher.plainText = input.toByteArray();
            cipher.encrypt();

            string answer = "aad74425bfd3f8ff22772f75be746df8";
            Assert.AreEqual(answer, cipher.cipherText.toHexString());

            answer = "qtdEJb/T+P8idy91vnRt+A==";
            Assert.AreEqual(answer, Convert.ToBase64String(cipher.cipherText));
        }

        [TestMethod]
        public void CBCDecryptionTest()
        {
            string input = "qtdEJb/T+P8idy91vnRt+A==";
            string key = "YELLOW SUBMARINE";

            BlockCipher cipher = new BlockCipher.CBCMode();
            cipher.key = key.toByteArray();
            cipher.blockSize = key.Length;
            cipher.cipherText = Convert.FromBase64String(input);
            byte[] iv = new byte[cipher.blockSize];
            for (int i = 0; i < cipher.blockSize; i++)
                iv[i] = 0x00;
            cipher.IV = iv;
            cipher.decrypt();

            string answer = "ABCDEABCDEABCDEF";
            Assert.AreEqual(answer, cipher.plainText.toString());
        }

        [TestMethod]
        public void CBCEncryptionAndDecryption()
        {
            string plain = "This is the original message.";
            string key = "BLUISH SUBMARINE";

            //encrypt
            BlockCipher cipher = new BlockCipher.CBCMode();
            cipher.plainText = plain.toByteArray();
            cipher.key = key.toByteArray();
            cipher.encrypt();
            string base64Message = cipher.cipherText.toBase64String();

            //decrypt
            cipher = new BlockCipher.CBCMode();
            cipher.cipherText = base64Message.base64ToByteArray();
            cipher.key = key.toByteArray();
            cipher.decrypt();

            Assert.AreEqual(plain, cipher.plainText.toString());
        }

        [TestMethod]
        public void FindBlockSizeTest()
        {
            BlockCipher cipher = new BlockCipher.ECBMode();
            int output = cipher.findBlockSize();
            int answer = cipher.blockSize;
            Assert.AreEqual(answer, output);
        }

        [TestMethod]
        public void ValidatePCKS7PaddingECBTest()
        {
            BlockCipher cipher = new BlockCipher.ECBMode();
            string plainText = "ICE ICE BABY\x04\x04\x04\x04";
            cipher.plainText = plainText.toByteArray();
            bool isValid = false;
            byte[] plainTextOut = cipher.isValidPadding(out isValid);
            Assert.AreEqual("ICE ICE BABY", plainTextOut.toString());
            Assert.IsTrue(isValid);

            cipher = new BlockCipher.ECBMode();
            plainText = "ICE ICE BABY\x05\x05\x05\x05";
            cipher.plainText = plainText.toByteArray();
            isValid = false;
            try
            {
                cipher.isValidPadding(out isValid);
                Assert.Fail();
            }
            catch (InvalidPaddingException e)
            {
                Assert.IsNotNull(e.Message);
                Assert.IsFalse(isValid);
            }
            catch (Exception e)
            {
                Assert.IsNotNull(e.Message);
                Assert.Fail();
            }

            cipher = new BlockCipher.ECBMode();
            plainText = "ICE ICE BABY\x01\x02\x03\x04";
            cipher.plainText = plainText.toByteArray();
            isValid = false;
            try
            {
                cipher.isValidPadding(out isValid);
                Assert.Fail();
            }
            catch (InvalidPaddingException e)
            {
                Assert.IsNotNull(e.Message);
                Assert.IsFalse(isValid);
            }
            catch (Exception e)
            {
                Assert.IsNotNull(e.Message);
                Assert.Fail();
            }
        }

        [TestMethod]
        public void ValidatePCKS7PaddingCBCTest()
        {
            BlockCipher cipher = new BlockCipher.CBCMode();
            string plainText = "ICE ICE BABY\x04\x04\x04\x04";
            cipher.plainText = plainText.toByteArray();
            bool isValid = false;
            byte[] plainTextOut = cipher.isValidPadding(out isValid);
            Assert.AreEqual("ICE ICE BABY", plainTextOut.toString());
            Assert.IsTrue(isValid);

            cipher = new BlockCipher.CBCMode();
            plainText = "ICE ICE BABY\x05\x05\x05\x05";
            cipher.plainText = plainText.toByteArray();
            isValid = false;
            try
            {
                cipher.isValidPadding(out isValid);
                Assert.Fail();
            }
            catch (InvalidPaddingException e)
            {
                Assert.IsNotNull(e.Message);
                Assert.IsFalse(isValid);
            }
            catch (Exception e)
            {
                Assert.IsNotNull(e.Message);
                Assert.Fail();
            }

            cipher = new BlockCipher.CBCMode();
            plainText = "ICE ICE BABY\x01\x02\x03\x04";
            cipher.plainText = plainText.toByteArray();
            isValid = false;
            try
            {
                cipher.isValidPadding(out isValid);
                Assert.Fail();
            }
            catch (InvalidPaddingException e)
            {
                Assert.IsNotNull(e.Message);
                Assert.IsFalse(isValid);
            }
            catch (Exception e)
            {
                Assert.IsNotNull(e.Message);
                Assert.Fail();
            }
        }
    }
}
