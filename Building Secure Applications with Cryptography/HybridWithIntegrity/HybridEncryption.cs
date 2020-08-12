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

namespace Pluralsight.HybridWithIntegrity
{
    public class HybridEncryption
    {
        private readonly AesEncryption _aes = new AesEncryption();

        public EncryptedPacket EncryptData(byte[] original, RSAWithRSAParameterKey rsaParams)
        {
            var sessionKey = _aes.GenerateRandomNumber(32);
            var encryptedPacket = new EncryptedPacket { Iv = _aes.GenerateRandomNumber(16) };

            // Encrypt data with AES and AES Key with RSA
            encryptedPacket.EncryptedData = _aes.Encrypt(original, sessionKey, encryptedPacket.Iv);
            encryptedPacket.EncryptedSessionKey = rsaParams.EncryptData(sessionKey);

            using (var hmac = new HMACSHA256(sessionKey))
            {
                encryptedPacket.Hmac = hmac.ComputeHash(Combine(encryptedPacket.EncryptedData, encryptedPacket.Iv));
            }

            return encryptedPacket;
        }

        public byte[] DecryptData(EncryptedPacket encryptedPacket, RSAWithRSAParameterKey rsaParams)
        {
            // Decrypt AES Key with RSA and then decrypt data with AES.
            var decryptedSessionKey = rsaParams.DecryptData(encryptedPacket.EncryptedSessionKey);

            using (var hmac = new HMACSHA256(decryptedSessionKey))
            {
                var hmacToCheck = hmac.ComputeHash(Combine(encryptedPacket.EncryptedData, encryptedPacket.Iv));

                if (!Compare(encryptedPacket.Hmac, hmacToCheck))
                {
                    throw new CryptographicException("HMAC for decryption does not match encrypted packet.");
                }
            }

            var decryptedData = _aes.Decrypt(encryptedPacket.EncryptedData, decryptedSessionKey, encryptedPacket.Iv);

            return decryptedData;
        }

        private static byte[] Combine(byte[] first, byte[] second)
        {
            var ret = new byte[first.Length + second.Length];

            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);

            return ret;
        }

        private static bool Compare(byte[] array1, byte[] array2)
        {
            var result = array1.Length == array2.Length;

            for (var i = 0; i < array1.Length && i < array2.Length; ++i)
            {
                result &= array1[i] == array2[i];
            }

            return result;
        }

        // Don't use this method for comparing byte arrays.
        // It is left here as an example.
        private static bool CompareUnSecure(byte[] array1, byte[] array2)
        {
            if (array1.Length != array2.Length)
            {
                return false;
            }

            for (int i = 0; i < array1.Length; ++i)
            {
                if (array1[i] != array2[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}
