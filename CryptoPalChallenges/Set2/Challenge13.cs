using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cipher;
using Extensions;

namespace CryptoPalChallenges.Set2
{
    public partial class Set2
    {
        public static void doChallenge13()
        {
            //in this case, we want the key available to the attacker, so let's store it here
            GenerateAESChallengeKey();
            var key = ChallengeKey;

            //in order to do this challenge, we need to manipulate the input to the oracle so that we change the user profile to "admin"            

            #region attack it
            string emailAddress = "aname@bar.com";
            string cookie = createCookieFor(emailAddress);
            //at this point, our cookie should look like:
            //  Block 0:    email=aname@bar.
            //  Block 1:    com&uid=10&role=
            //  Block 2:    user[padding]
            //so, our role value sits in block 2
            var cookieCipherText = oracle13Encrypt(cookie.toByteArray());
            var cookieCipherTextList = cookieCipherText.toList(key.Length);

            //let's create our replacement block that we can use.
            byte[] adminPlainText = "admin".toByteArray();
            //pad this with zeroes so we get a padded block we can use straight away
            adminPlainText = adminPlainText.toString().PadRight(16, '\0').toByteArray();
            //using the same method as above, we want to shift our new block to the right point so that the "admin" part is at the beginning of a block when we use the oracle
            StringBuilder sb = new StringBuilder("xxxxxxxxxx");
            sb.Append(adminPlainText.toString());
            string adminCookie = createCookieFor(sb.ToString());
            byte[] adminCipherText = oracle13Encrypt(adminCookie.toByteArray());
            var adminCipherTextList = adminCipherText.toList(key.Length);   //the block we want here is in block 1

            var attackCipher = new List<byte[]>();      //this will be the List we now build up to have the admin block in it
            attackCipher.Add(cookieCipherTextList[0]);
            attackCipher.Add(cookieCipherTextList[1]);
            attackCipher.Add(adminCipherTextList[1]);

            var cipherText = attackCipher.toByteArray();    //now we can feed this into the decryption oracle and see if we have escalated the role
            #endregion

            //now, let's check what out decrypted output looks like and raise a flag if we have managed to change the user to "admin"
            var plainText = oracle13Decrypt(cipherText);
            Dictionary<string, string> profileDictionary = cookieParser(plainText.toString());
            string role = profileDictionary["role"];
            if (role.Equals("admin"))
                Console.WriteLine("User escalated, job done");
            else
                Console.WriteLine("User profile is " + role);
        }

        public static byte[] oracle13Encrypt(byte[] plainText)
        {
            //this oracle must encrypt the plainText (which is the user profile from the cookie generation), using ECB
            BlockCipher cipher = new BlockCipher.ECBMode();
            cipher.plainText = plainText;
            cipher.key = ChallengeKey;
            cipher.encrypt();

            return cipher.cipherText;
        }

        public static byte[] oracle13Decrypt(byte[] cipherText)
        {
            BlockCipher cipher = new BlockCipher.ECBMode();
            cipher.cipherText = cipherText;
            cipher.key = ChallengeKey;
            cipher.decrypt();

            return cipher.plainText;
        }

        public static string createCookieFor(string input)
        {
            string output;

            input = input.Replace("&", "").Replace("=", "");
            var cookieDictionary = new Dictionary<string, string>();
            cookieDictionary.Add("email", input);
            cookieDictionary.Add("uid", "10");
            cookieDictionary.Add("role", "user");

            output = cookieParser(cookieDictionary);

            return output;
        }

        public static Dictionary<string, string> cookieParser(string input)
        {
            var output = new Dictionary<string, string>();
            string[] elements = input.Split('&');
            foreach (string pair in elements)
            {
                string[] data = pair.Split('=');
                output.Add(data[0], data[1]);
            }
            return output;
        }

        public static string cookieParser(Dictionary<string, string> input)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("email=");
            sb.Append(input["email"]);
            sb.Append("&");
            sb.Append("uid=");
            sb.Append(input["uid"]);
            sb.Append("&");
            sb.Append("role=");
            sb.Append(input["role"]);

            return sb.ToString();
        }
    }
}
