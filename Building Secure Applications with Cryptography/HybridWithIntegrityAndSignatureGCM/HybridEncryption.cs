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

namespace Pluralsight.HybridWithIntegrityAndSignatureGCM
{
    public class HybridEncryption
    {
        private readonly AesGCMEncryption _aes = new AesGCMEncryption();

        public EncryptedPacket EncryptData(byte[] original, NewRSA rsaParams,
                                           NewDigitalSignature digitalSignature)
        {
            // Create AES session key.
            var sessionKey = _aes.GenerateRandomNumber(32);

            var encryptedPacket = new EncryptedPacket { Iv = _aes.GenerateRandomNumber(12) };

            // Encrypt data with AES-GCM
            (byte[] ciphereText, byte[] tag) encrypted = _aes.Encrypt(original, sessionKey, encryptedPacket.Iv, null);

            encryptedPacket.EncryptedData = encrypted.ciphereText;
            encryptedPacket.Tag = encrypted.tag;
            encryptedPacket.EncryptedSessionKey = rsaParams.Encrypt(sessionKey);

            var temp = Combine(encryptedPacket.EncryptedData, encryptedPacket.Iv);
            (byte[] signature, byte[] hash) signature = digitalSignature.SignData(Combine(temp, encryptedPacket.Tag));
            encryptedPacket.Signature = signature.hash;
            encryptedPacket.Hmac = signature.signature;

            return encryptedPacket;
        }

        public byte[] DecryptData(EncryptedPacket encryptedPacket, NewRSA rsaParams,
                                  NewDigitalSignature digitalSignature)
        {
            var decryptedSessionKey = rsaParams.Decrypt(encryptedPacket.EncryptedSessionKey);


            if (!digitalSignature.VerifySignature(encryptedPacket.Hmac,
                                      encryptedPacket.Signature))
            {
                throw new CryptographicException(
                    "Digital Signature can not be verified.");
            }

            var decryptedData = _aes.Decrypt(encryptedPacket.EncryptedData, decryptedSessionKey,
                                             encryptedPacket.Iv, encryptedPacket.Tag, null);

            return decryptedData;
        }

        private static byte[] Combine(byte[] first, byte[] second)
        {
            var ret = new byte[first.Length + second.Length];

            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);

            return ret;
        }
    }
}
