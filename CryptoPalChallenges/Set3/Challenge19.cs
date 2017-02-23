using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Extensions;
using Cipher;
using System.IO;
using System.Data;

namespace CryptoPalChallenges.Set3
{
    public partial class Set3
    {
        public static void doChallenge19()
        {
            GenerateAESChallengeKey();

            //get the given plaintexts, create a list of their bytes for use
            string[] lines = File.ReadAllLines(@"..\..\..\CryptoPalChallenges\Files\Set3Challenge19.txt");
            var lineList = new List<byte[]>();
            foreach (string line in lines)
                lineList.Add(line.base64ToByteArray());

            //create cipher and encrypt each line of the inputs
            var cipherTextList = new List<byte[]>();
            CTRMode cipher = new CTRMode();
            byte[] nonce = new byte[cipher.blockSize / 2];
            for (int i = 0; i < nonce.Length; i++)
                nonce[i] = 0;
            cipher.nonce = nonce;
            cipher.key = ChallengeKey;

            int maxLength = 0;
            foreach (byte[] plainText in lineList)
            {
                cipher.plainText = plainText;
                cipher.encrypt();
                cipherTextList.Add(cipher.cipherText);
                if (cipher.cipherText.Length > maxLength)
                    maxLength = cipher.cipherText.Length;
            }

            DataTable scoring = new DataTable();
            scoring.Columns.Add("BytePosition", typeof(int));
            scoring.Columns.Add("ByteValue", typeof(byte));
            scoring.Columns.Add("CumScore", typeof(int));

            //we can now try work out each byte of the keystream. let's follow the byte-by-byte process we have done before
            foreach (byte[] cipherText in cipherTextList)
            {
                for (int positionIndex = 0; positionIndex < maxLength; positionIndex++)
                {
                    if (positionIndex > (cipherText.Length - 1))
                        break;
                    for (byte i = byte.MinValue; i < byte.MaxValue; i++)
                    {
                        byte xorResult = (byte)(i ^ cipherText[positionIndex]);
                        int score = ScoreString(xorResult.toString());
                        scoring.Rows.Add(positionIndex, i, score);
                    }
                }
            }

            //TODO: implement SQL DB so we can access the scores easily
        }

        private static int ScoreString(string _input)
        {
            int score = 0;
            foreach (char c in _input)
            {
                switch (c)
                {
                    case 'e':
                    case 'E':
                        score = score + 12;
                        break;
                    case 't':
                    case 'T':
                        score = score + 9;
                        break;
                    case 'a':
                    case 'A':
                        score = score + 8;
                        break;
                    case 'o':
                    case 'O':
                        score = score + 7;
                        break;
                    case 'i':
                    case 'I':
                        score = score + 6;
                        break;
                    case 'n':
                    case 'N':
                        score = score + 6;
                        break;
                    case ' ':
                        score = score + 5;
                        break;
                }
                byte asciiByte = c.ToString().toByte();
                if ((asciiByte > 0x30) && (asciiByte < 0x7A))
                    score += 1;
            }

            return score;
        }
    }
}
