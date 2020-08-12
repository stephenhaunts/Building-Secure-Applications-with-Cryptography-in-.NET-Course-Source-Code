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

namespace Pluralsight.Hashing
{
    static class Program
    {
        static void Main()
        {
            const string originalMessage = "Original Message to hash";
            const string originalMessage2 = "Or1ginal Message to hash";

            Console.WriteLine("Secure HashData Demonstration in .NET");
            Console.WriteLine("---------------------------------");
            Console.WriteLine();
            Console.WriteLine("Original Message 1 : " + originalMessage);
            Console.WriteLine("Original Message 2 : " + originalMessage2);
            Console.WriteLine();

            var md5HashedMessage = HashData.ComputeHashMd5(Encoding.UTF8.GetBytes(originalMessage));
            var md5HashedMessage2 = HashData.ComputeHashMd5(Encoding.UTF8.GetBytes(originalMessage2));

            var sha1HashedMessage = HashData.ComputeHashSha1(Encoding.UTF8.GetBytes(originalMessage));
            var sha1HashedMessage2 = HashData.ComputeHashSha1(Encoding.UTF8.GetBytes(originalMessage2));

            var sha256HashedMessage = HashData.ComputeHashSha256(Encoding.UTF8.GetBytes(originalMessage));
            var sha256HashedMessage2 = HashData.ComputeHashSha256(Encoding.UTF8.GetBytes(originalMessage2));

            var sha512HashedMessage = HashData.ComputeHashSha512(Encoding.UTF8.GetBytes(originalMessage));
            var sha512HashedMessage2 = HashData.ComputeHashSha512(Encoding.UTF8.GetBytes(originalMessage2));

            Console.WriteLine();
            Console.WriteLine("MD5 Hashes");
            Console.WriteLine();
            Console.WriteLine("Message 1 hash = " + Convert.ToBase64String(md5HashedMessage));
            Console.WriteLine("Message 2 hash = " + Convert.ToBase64String(md5HashedMessage2));
            Console.WriteLine();
            Console.WriteLine("SHA 1 Hashes");
            Console.WriteLine();
            Console.WriteLine("Message 1 hash = " + Convert.ToBase64String(sha1HashedMessage));
            Console.WriteLine("Message 2 hash = " + Convert.ToBase64String(sha1HashedMessage2));
            Console.WriteLine();

            Console.WriteLine("SHA 256 Hashes");
            Console.WriteLine();
            Console.WriteLine("Message 1 hash = " + Convert.ToBase64String(sha256HashedMessage));
            Console.WriteLine("Message 2 hash = " + Convert.ToBase64String(sha256HashedMessage2));
            Console.WriteLine();
            Console.WriteLine("SHA 512 Hashes");
            Console.WriteLine();
            Console.WriteLine("Message 1 hash = " + Convert.ToBase64String(sha512HashedMessage));
            Console.WriteLine("Message 2 hash = " + Convert.ToBase64String(sha512HashedMessage2));
            Console.WriteLine();
            Console.ReadLine();
        }
    }
}
