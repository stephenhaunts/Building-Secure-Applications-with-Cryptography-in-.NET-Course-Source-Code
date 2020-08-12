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

namespace Pluralsight.HybridWithIntegrityAndSignature
{
    static class Program
    {
        static void Main()
        {
            const string original = "Very secret and important information that can not fall into the wrong hands.";

            var hybrid = new HybridEncryption();

            var rsaParams = new RSAWithRSAParameterKey();
            rsaParams.AssignNewKey();

            
            Console.WriteLine("Hybrid Encryption (AES-GCM) with Integrity Check in .NET");
            Console.WriteLine("--------------------------------------------------------");
            Console.WriteLine();

            try
            {
                var encryptedBlock = hybrid.EncryptData(Encoding.UTF8.GetBytes(original), rsaParams);

                var decrpyted = hybrid.DecryptData(encryptedBlock, rsaParams);

                Console.WriteLine("Original Message = " + original);
                Console.WriteLine();
                Console.WriteLine("Message After Decryption = " + Encoding.UTF8.GetString(decrpyted));
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine("Error : " + ex.Message);
            }

            Console.ReadLine();
        }
    }
}
