using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptoPalChallenges;

namespace UnitTests
{
    [TestClass]
    public class ExtensionTests
    {
        [TestMethod]
        public void HexStringToByteArrayTest()
        {
            string input = "313233";
            byte[] output = input.hexToByteArray();
            Assert.AreEqual(0x31, output[0]);
            Assert.AreEqual(0x32, output[1]);
            Assert.AreEqual(0x33, output[2]);
            Assert.AreEqual(3, output.Length);
        }

        [TestMethod]
        public void UnicodeStringToByteArray()
        {
            string input = "tHiS!";
            byte[] output = input.toByteArray();
            Assert.AreEqual(5, output.Length);
            Assert.AreEqual(0x74, output[0]);
            Assert.AreEqual(0x48, output[1]);
            Assert.AreEqual(0x69, output[2]);
            Assert.AreEqual(0x53, output[3]);
            Assert.AreEqual(0x21, output[4]);
        }
    }
}
