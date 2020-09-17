/*
MIT License

Copyright (c) 2020

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
using System;
using System.Security.Cryptography;
using System.Text;

namespace Pluralsight.ProtectedDataExample
{
    class Program
    {
        static AesGCMEncryption aesGCM = new AesGCMEncryption();

        static void Main(string[] args)
        {
            ProtectedDataTest();

            EncryptAndDecryptWithProtectedKey();
        }

        private static void EncryptAndDecryptWithProtectedKey()
        {
            string original = "Text to encrypt";
            Console.WriteLine("Original Text = ", original);


            // Create a key and nonce. Encrypt our text with AES/
            var gcmKey = aesGCM.GenerateRandomNumber(32);
            var nonce = aesGCM.GenerateRandomNumber(12);
            var result = EncryptText(original, gcmKey, nonce);

            // Create some entropy and protect the AES key.
            var entropy = aesGCM.GenerateRandomNumber(16);
            byte[] protectedKey = Protected.Protect(gcmKey, entropy, DataProtectionScope.CurrentUser);

            // Decrypt the text with AES. First the AES key has to be retrieved with DPAPI.
            string decryptedText = DecryptText(result.encrypted, nonce, result.tag, protectedKey, entropy);
            Console.WriteLine("Decrypted Text = ", decryptedText);
        }

        private static (byte [] encrypted, byte [] tag) EncryptText(string original, byte[] gcmKey, byte[] nonce)
        {     
            return aesGCM.Encrypt(Encoding.UTF8.GetBytes(original), gcmKey, nonce, Encoding.UTF8.GetBytes("some metadata"));     
        }

        private static string DecryptText(byte[] encrypted, byte[] nonce, byte[] tag, byte[] protectedKey, byte[] entropy)
        { 
            byte[] key = Protected.Unprotect(protectedKey, entropy, DataProtectionScope.CurrentUser);

            byte[] decryptedText = aesGCM.Decrypt(encrypted, key, nonce, tag, Encoding.UTF8.GetBytes("some metadata"));

            return Encoding.UTF8.GetString(decryptedText);
        }
        
        private static void ProtectedDataTest()
        {
            var encrypted = Protected.Protect("Mary had a little lamb", "8wef5juy2389f4", DataProtectionScope.CurrentUser);
            Console.WriteLine(encrypted);

            var decrypted = Protected.Unprotect(encrypted, "8wef5juy2389f4", DataProtectionScope.CurrentUser);
            Console.WriteLine(decrypted);
        }
    }
}
