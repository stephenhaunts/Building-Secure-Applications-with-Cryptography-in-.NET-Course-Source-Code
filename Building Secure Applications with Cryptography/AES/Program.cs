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

namespace Pluralsight.AES
{
    static class Program
    {
        static void Main(string[] args)
        {
            TestAesGCM();

            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine();

            TestAesCBC();

            Console.ReadLine();
        }

        private static void TestAesCBC()
        {
            const string original = "Text to encrypt";
            var aes = new AesEncryption();
            var key = aes.GenerateRandomNumber(32);
            var iv = aes.GenerateRandomNumber(16);


            var encrypted = aes.Encrypt(Encoding.UTF8.GetBytes(original), key, iv);
            var decrypted = aes.Decrypt(encrypted, key, iv);

            var decryptedMessage = Encoding.UTF8.GetString(decrypted);

            Console.WriteLine("AES Encryption Demonstration in .NET");
            Console.WriteLine("------------------------------------");
            Console.WriteLine();
            Console.WriteLine("Original Text = " + original);
            Console.WriteLine("Encrypted Text = " + Convert.ToBase64String(encrypted));
            Console.WriteLine("Decrypted Text = " + decryptedMessage);
        }

        private static void TestAesGCM()
        {
            const string original = "Text to encrypt";

            var aesGCM = new AesGCMEncryption();

            var gcmKey = aesGCM.GenerateRandomNumber(32);
            var nonce = aesGCM.GenerateRandomNumber(12);

            try
            {
                (byte[] ciphereText, byte[] tag) result = aesGCM.Encrypt(Encoding.UTF8.GetBytes(original), gcmKey, nonce, Encoding.UTF8.GetBytes("some metadata"));
                byte[] decryptedText = aesGCM.Decrypt(result.ciphereText, gcmKey, nonce, result.tag, Encoding.UTF8.GetBytes("some metadata"));

                Console.WriteLine("AES GCM Encryption Demonstration in .NET");
                Console.WriteLine("----------------------------------------");
                Console.WriteLine();
                Console.WriteLine("Original Text = " + original);
                Console.WriteLine("Encrypted Text = " + Convert.ToBase64String(result.ciphereText));
                Console.WriteLine("Decrypted Text = " + Encoding.UTF8.GetString(decryptedText));
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine(ex.Message);
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}
