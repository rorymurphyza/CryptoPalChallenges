using System;
using System.Text;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptoPalChallenges
{
    /// <summary>
    /// All testing for Set 2 methods and functions
    /// </summary>
    [TestClass]
    public class Set2Test
    {
        public Set2Test()
        {
            
        }

        private TestContext testContextInstance;

        /// <summary>
        ///Gets or sets the test context which provides
        ///information about and functionality for the current test run.
        ///</summary>
        public TestContext TestContext
        {
            get
            {
                return testContextInstance;
            }
            set
            {
                testContextInstance = value;
            }
        }

        #region Additional test attributes
        //
        // You can use the following additional attributes as you write your tests:
        //
        // Use ClassInitialize to run code before running the first test in the class
        // [ClassInitialize()]
        // public static void MyClassInitialize(TestContext testContext) { }
        //
        // Use ClassCleanup to run code after all tests in a class have run
        // [ClassCleanup()]
        // public static void MyClassCleanup() { }
        //
        // Use TestInitialize to run code before running each test 
        // [TestInitialize()]
        // public void MyTestInitialize() { }
        //
        // Use TestCleanup to run code after each test has run
        // [TestCleanup()]
        // public void MyTestCleanup() { }
        //
        #endregion

        [TestMethod]
        public void UtilsPKCSPadStringToBlockSize()
        {
            int blockSize = 20;
            string input = "YELLOW SUBMARINE";
            string output = CryptoPalChallenges.Utils.PKCSPadStringToBlockSize(input, blockSize);
            string answer = "YELLOW SUBMARINE\u0004\u0004\u0004\u0004";
            int outputLength = output.Length;
            
            Assert.AreEqual(answer, output);
            Assert.AreEqual(outputLength, blockSize);
        }

        [TestMethod]
        public void ECBEncryption()
        {
            string input = "ABCDEABCDEABCDEF";
            string key = "YELLOW SUBMARINE";
            byte[] output = BlockCipherdep.ECBMode.encrypt(Utils.ConvertStringToByteArray(input), Utils.ConvertStringToByteArray(key));
            string answer64 = "qtdEJb/T+P8idy91vnRt+A==";
            string answerHex = "aad74425bfd3f8ff22772f75be746df8";

            Assert.AreEqual(answer64, Convert.ToBase64String(output));
            Assert.AreEqual(answerHex, Utils.ConvertByteArrayToHexString(output));
        }

        [TestMethod]
        public void ECBDecryption()
        {
            string input64 = "FYtzWIwGx67LrZRSLYdiOg==";
            string key = "YELLOW SUBMARINE";
            byte[] output = CryptoPalChallenges.BlockCipherdep.ECBMode.decrypt(Convert.FromBase64String(input64), Utils.ConvertStringToByteArray(key));
            string answer = "ABCDE";

            Assert.AreEqual(answer, Utils.ConvertByteArrayToString(output).Trim('\0'));
        }

        [TestMethod]
        public void CBCEncryption()
        {
            string input = "ABCDEABCDEABCDEF";
            string key = "YELLOW SUBMARINE";

            BlockCipherdep cipher = new BlockCipherdep();
            cipher.blockSize = key.Length;
            cipher.key = Utils.ConvertStringToByteArray(key);
            byte[] iv = new byte[key.Length];
            for (int i = 0; i < iv.Length; i++)
                iv[i] = 0x00;
            cipher.IV = iv;
            cipher.plainText = Utils.ConvertStringToByteArray(input);

            CryptoPalChallenges.BlockCipherdep.CBCMode.encrypt(cipher);
            byte[] output = cipher.cipherText;

            string answer = "aad74425bfd3f8ff22772f75be746df8";
            Assert.AreEqual(answer, Utils.ConvertByteArrayToHexString(output));
            answer = "qtdEJb/T+P8idy91vnRt+A==";
            Assert.AreEqual(answer, Convert.ToBase64String(output));
        }

        [TestMethod]
        public void CBCDecryption()
        {
            string input = "qtdEJb/T+P8idy91vnRt+A==";
            string key = "YELLOW SUBMARINE";

            BlockCipherdep cipher = new BlockCipherdep();
            cipher.key = Utils.ConvertStringToByteArray(key);
            cipher.blockSize = key.Length;
            cipher.cipherText = Convert.FromBase64String(input);
            byte[] iv = new byte[cipher.blockSize];
            for (int i = 0; i < cipher.blockSize; i++)
                iv[i] = 0x00;
            cipher.IV = iv;

            CryptoPalChallenges.BlockCipherdep.CBCMode.decrypt(cipher);
            byte[] output = cipher.plainText;

            string answer = "ABCDEABCDEABCDEF";
            Assert.AreEqual(answer, Utils.ConvertByteArrayToString(output));

        }

        [TestMethod]
        public void ByteArrayToList()
        {
            string input = "1234567890";
            List<byte[]> output = Utils.ConvertByteArrayToList(Utils.ConvertStringToByteArray(input), 5);
            Assert.AreEqual(2, output.Count);
            Assert.AreEqual(output[0].Length, output[1].Length);
            byte[] answer1 = Utils.ConvertStringToByteArray("12345");
            byte[] answer2 = Utils.ConvertStringToByteArray("67890");
            Assert.AreEqual(answer1[0], output[0][0]);
            Assert.AreEqual(answer1[3], output[0][3]);
            Assert.AreEqual(answer2[1], output[1][1]);
            Assert.AreEqual(answer2[3], output[1][3]);

            input = "abcdefghijklmnopqrstuvwxyzABCDEF";
            output = Utils.ConvertByteArrayToList(Utils.ConvertStringToByteArray(input), 16);
            Assert.AreEqual(2, output.Count);
            Assert.AreEqual(output[1].Length, output[0].Length);
            Assert.AreEqual(0x61, output[0][0]);
            Assert.AreEqual(0x63, output[0][2]);
            Assert.AreEqual(0x41, output[1][10]);
        }

        [TestMethod]
        public void ListToByteArray()
        {
            string input = "1234567890";
            List<byte[]> temp = Utils.ConvertByteArrayToList(Utils.ConvertStringToByteArray(input), 2);
            string output = Utils.ConvertByteArrayToString(Utils.ConvertListToByteArray(temp));
            Assert.AreEqual(input, output);
        }

        [TestMethod]
        public void validatePadding()
        {
            //Check for correct padding
            string input = "test";
            byte[] inputWithPadding = Utils.PKCSPadByteArrayToBlockSize(Utils.ConvertStringToByteArray(input), 16);
            bool validPadding = false;
            byte[] output = Utils.isValidPadding(inputWithPadding, out validPadding);
            Assert.AreEqual(input, Utils.ConvertByteArrayToString(output));
            Assert.AreEqual(true, validPadding);

            input = "ICE ICE BABY\x04\x04\x04\x04";
            validPadding = false;
            output = Utils.isValidPadding(Utils.ConvertStringToByteArray(input), out validPadding);
            Assert.AreEqual("ICE ICE BABY", Utils.ConvertByteArrayToString(output));
            Assert.IsTrue(validPadding);

            //Check for padding where the padding numbers are incorrect
            try
            {
                input = "ICE ICE BABY\x01\x02\x03\x04";
                validPadding = false;
                output = Utils.isValidPadding(Utils.ConvertStringToByteArray(input), out validPadding);
                Assert.Fail("Failed on inconsistent padding numbers");
            }
            catch (InvalidPaddingException e)
            {
                Assert.IsFalse(validPadding);
                Assert.IsNotNull(e.Message);
            }
            catch (Exception e)
            {
                Assert.Fail("Wrong exception thrown: " + e.Message);
            }

            //check for case where no padding/block size can't be right
            try
            {
                byte[] inputWithoutPadding = Utils.ConvertStringToByteArray(input);
                validPadding = false;
                output = Utils.isValidPadding(inputWithoutPadding, out validPadding);
                Assert.Fail("Failed on input length");
            }
            catch (InvalidPaddingException e)
            {
                Assert.IsFalse(validPadding);
                Assert.IsNotNull(e.Message);
            }
            catch (Exception e)
            {
                Assert.Fail("Wrong exception thrown: " + e.Message);
            }

            //check for case where number in padding and actual count are different
            try
            {
                input = "ICE ICE BABY\x05\x05\x05\x05";
                validPadding = false;
                output = Utils.isValidPadding(Utils.ConvertStringToByteArray(input), out validPadding);
                Assert.Fail("Failed on wrong padding length and number");
            }
            catch (InvalidPaddingException e)
            {
                Assert.IsFalse(validPadding);
                Assert.IsNotNull(e.Message);
            }
            catch (Exception e)
            {
                Assert.Fail("Wrong exception thrown: " + e.Message);
            }
        }
    }
}
