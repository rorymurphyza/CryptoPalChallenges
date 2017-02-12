using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptoPalChallenges;

namespace UnitTests
{
    [TestClass]
    public class Set1Test
    {
        //Test for Set 1, Set 2
        [TestMethod]
        public void ConvertHexStringToBase64()
        {
            string input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
            string output = input.hexToByteArray().toBase64String();
            string answer = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"; //The answer as per the challenge
            Assert.AreEqual(answer, output);
        }

        //Test for Set 1, Challenge 2
        [TestMethod]
        public void XorEqualLength()
        {
            string input1 = "1c0111001f010100061a024b53535009181c";
            string input2 = "686974207468652062756c6c277320657965";
            string output = Xor.XorEqualLength(input1, input2);
            string answer = "746865206b696420646f6e277420706c6179";
            Assert.AreEqual(answer, output);
        }        
        
        //Set 1, Challenge 5
        [TestMethod]
        public void EncryptWithRepeatingXOR()
        {
            string input = string.Format("Burning 'em, if you ain't quick and nimble{0}I go crazy when I hear a cymbal", Convert.ToChar(0x0A));
            string key = "ICE";
            string answer = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

            string output = CryptoPalChallenges.Encrypter.RepeatingXOR(input, key);
            Assert.AreEqual(answer, output);
        }

        //Set 1, Challenge 6
        [TestMethod]
        public void HammingDistanceTest()
        {
            string input1 = "this is a test";
            string input2 = "wokka wokka!!!";
            int answer = 37;
            int output = CryptoPalChallenges.Decrypter.CalculateHammingDistance(input1, input2);
            Assert.AreEqual(answer, output);
        }
        [TestMethod]
        public void Base64ToStringTest()
        {
            string input = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
            string answer = "I'm killing your brain like a poisonous mushroom";
            string output = CryptoPalChallenges.Utils.ConvertBase64ToString(input);
            Assert.AreEqual(answer, output);
        }
        [TestMethod]
        public void Base64ToHexStringTest()
        {
            string input = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
            string answer = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
            string output = CryptoPalChallenges.Utils.ConvertBase64ToHexString(input);
            Assert.AreEqual(answer, output);
        }
    }
}
