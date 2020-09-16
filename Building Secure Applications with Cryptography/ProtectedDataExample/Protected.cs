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
    public class Protected
    { 
        public static string Protect(string stringToEncrypt, string optionalEntropy, DataProtectionScope scope)
        {      
            byte[] encryptedData = ProtectedData.Protect(
                    Encoding.UTF8.GetBytes(stringToEncrypt)
                    , optionalEntropy != null ? Encoding.UTF8.GetBytes(optionalEntropy) : null
                    , scope);

            return Convert.ToBase64String(encryptedData);
        }

        public static string Unprotect(string encryptedString, string optionalEntropy, DataProtectionScope scope)
        {          
            byte[] decrypted = ProtectedData.Unprotect(
                    Convert.FromBase64String(encryptedString)
                    , optionalEntropy != null ? Encoding.UTF8.GetBytes(optionalEntropy) : null
                    , scope);

            return Encoding.UTF8.GetString(decrypted);
        }

        public static byte[] Protect(byte[] stringToEncrypt, byte[] optionalEntropy, DataProtectionScope scope)
        {
            byte[] encryptedData = ProtectedData.Protect(stringToEncrypt
                    , optionalEntropy != null ? optionalEntropy : null
                    , scope);

            return encryptedData;
        }

        public static byte[] Unprotect(byte[] encryptedString, byte[] optionalEntropy, DataProtectionScope scope)
        {
            byte[] decrypted = ProtectedData.Unprotect(encryptedString,
                    optionalEntropy != null ? optionalEntropy : null,
                    scope);

            return decrypted;
        }
    }
}
