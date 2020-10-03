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
using System.Text;

namespace Pluralsight.Asymetric
{
    static class Program
    {
        static void Main()
        {
            RsaWithRsaParameterKey();

            //
            // Not Supported on MacOS
            //
            //RsaWithCsp();

            Console.ReadLine();
        }

        private static void RsaWithCsp()
        {
            var rsaCsp = new RsaWithCspKey();
            const string original = "Text to encrypt";

            rsaCsp.AssignNewKey();

            var encryptedCsp = rsaCsp.EncryptData(Encoding.UTF8.GetBytes(original));
            var decryptedCsp = rsaCsp.DecryptData(encryptedCsp);

            rsaCsp.DeleteKeyInCsp();

            Console.WriteLine();
            Console.WriteLine("CSP Based Key");
            Console.WriteLine();
            Console.WriteLine("   Original Text = " + original);
            Console.WriteLine();
            Console.WriteLine("   Encrypted Text = " + Convert.ToBase64String(encryptedCsp));
            Console.WriteLine();
            Console.WriteLine("   Decrypted Text = " + Encoding.Default.GetString(decryptedCsp));
        }

        private static void RsaWithRsaParameterKey()
        {
            var rsaParams = new RSAWithRSAParameterKey();
            const string original = "Text to encrypt";

            rsaParams.AssignNewKey();

            var encryptedRsaParams = rsaParams.EncryptData(Encoding.UTF8.GetBytes(original));
            var decryptedRsaParams = rsaParams.DecryptData(encryptedRsaParams);


            Console.WriteLine("RSA Encryption Demonstration in .NET");
            Console.WriteLine("------------------------------------");
            Console.WriteLine();
            Console.WriteLine("In Memory Key");
            Console.WriteLine();
            Console.WriteLine("   Original Text = " + original);
            Console.WriteLine();
            Console.WriteLine("   Encrypted Text = " + Convert.ToBase64String(encryptedRsaParams));
            Console.WriteLine();
            Console.WriteLine("   Decrypted Text = " + Encoding.Default.GetString(decryptedRsaParams));
            Console.WriteLine();
            Console.WriteLine();
        }
    }
}
