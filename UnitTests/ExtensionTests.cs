using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptoPalChallenges;

namespace UnitTests
{
    [TestClass]
    public class ExtensionTests
    {
        [TestMethod]
        public void StringToByteArrayTest()
        {
            string input = "313233";
            byte[] output = input.hexToByteArray();
            Assert.AreEqual(0x31, output[0]);
            Assert.AreEqual(0x32, output[1]);
            Assert.AreEqual(0x33, output[2]);
            Assert.AreEqual(3, output.Length);
        }

        
    }
}
