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

namespace Pluralsight.HMAC
{
    static class Program
    {
        static void Main()
        {
            const string originalMessage = "Original Message to hash";
            const string originalMessage2 = "Original xessage to hash";

            Console.WriteLine("HMAC Demonstration in .NET");
            Console.WriteLine("--------------------------");
            Console.WriteLine();

            var key = Hmac.GenerateKey();

            var hmacMd5Message = Hmac.ComputeHmacmd5(Encoding.UTF8.GetBytes(originalMessage), key);
            var hmacMd5Message2 = Hmac.ComputeHmacmd5(Encoding.UTF8.GetBytes(originalMessage2), key);

            var hmacSha1Message = Hmac.ComputeHmacsha1(Encoding.UTF8.GetBytes(originalMessage), key);
            var hmacSha1Message2 = Hmac.ComputeHmacsha1(Encoding.UTF8.GetBytes(originalMessage2), key);

            var hmacSha256Message = Hmac.ComputeHmacsha256(Encoding.UTF8.GetBytes(originalMessage), key);
            var hmacSha256Message2 = Hmac.ComputeHmacsha256(Encoding.UTF8.GetBytes(originalMessage2), key);

            var hmacSha512Message = Hmac.ComputeHmacsha512(Encoding.UTF8.GetBytes(originalMessage), key);
            var hmacSha512Message2 = Hmac.ComputeHmacsha512(Encoding.UTF8.GetBytes(originalMessage2), key);

            Console.WriteLine();
            Console.WriteLine("MD5 HMAC");
            Console.WriteLine();
            Console.WriteLine("Message 1 hash = " + Convert.ToBase64String(hmacMd5Message));
            Console.WriteLine("Message 2 hash = " + Convert.ToBase64String(hmacMd5Message2));

            Console.WriteLine();
            Console.WriteLine("SHA 1 HMAC");
            Console.WriteLine();
            Console.WriteLine("Message 1 hash = " + Convert.ToBase64String(hmacSha1Message));
            Console.WriteLine("Message 2 hash = " + Convert.ToBase64String(hmacSha1Message2));

            Console.WriteLine();
            Console.WriteLine("SHA 256 HMAC");
            Console.WriteLine();
            Console.WriteLine("Message 1 hash = " + Convert.ToBase64String(hmacSha256Message));
            Console.WriteLine("Message 2 hash = " + Convert.ToBase64String(hmacSha256Message2));

            Console.WriteLine();
            Console.WriteLine("SHA 512 HMAC");
            Console.WriteLine();
            Console.WriteLine("Message 1 hash = " + Convert.ToBase64String(hmacSha512Message));
            Console.WriteLine("Message 2 hash = " + Convert.ToBase64String(hmacSha512Message2));
            Console.WriteLine();

            Console.ReadLine();
        }
    }
}
