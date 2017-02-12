using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptoPalChallenges;
using System.Collections.Generic;
using Extensions;

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

        [TestMethod]
        public void ByteArrayToList()
        {
            string input = "1234567890";
            List<byte[]> output = input.toByteArray().toList(5);
            Assert.AreEqual(2, output.Count);
            Assert.AreEqual(output[0].Length, output[1].Length);
            byte[] answer1 = Utils.ConvertStringToByteArray("12345");
            byte[] answer2 = Utils.ConvertStringToByteArray("67890");
            Assert.AreEqual(answer1[0], output[0][0]);
            Assert.AreEqual(answer1[3], output[0][3]);
            Assert.AreEqual(answer2[1], output[1][1]);
            Assert.AreEqual(answer2[3], output[1][3]);

            input = "abcdefghijklmnopqrstuvwxyzABCDEF";
            output = input.toByteArray().toList(16);
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
            List<byte[]> temp = input.toByteArray().toList(2);
            string output = temp.toByteArray().toString();
            Assert.AreEqual(input, output);
        }
    }
}
