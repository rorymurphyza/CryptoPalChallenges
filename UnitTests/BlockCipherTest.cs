using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cipher;
using CryptoPalChallenges;

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
        }

        [TestMethod]
        public void ECBEncryption()
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
        public void ECBDecryption()
        {
            BlockCipher cipher = new BlockCipher.ECBMode();
            cipher.key = "YELLOW SUBMARINE".toByteArray();
            string input64 = "FYtzWIwGx67LrZRSLYdiOg==";
            cipher.cipherText = input64.base64ToByteArray();
            cipher.decrypt();

            string answer = "ABCDE";

            Assert.AreEqual(answer, cipher.plainText.toString());
        }
    }
}
