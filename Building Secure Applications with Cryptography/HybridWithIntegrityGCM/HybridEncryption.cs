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

namespace Pluralsight.HybridWithIntegrityAndSignature
{
    public class HybridEncryption
    {
        private readonly AesGCMEncryption _aes = new AesGCMEncryption();

        public EncryptedPacket EncryptData(byte[] original, RSAWithRSAParameterKey rsaParams)
        {
            var sessionKey = _aes.GenerateRandomNumber(32);

            var encryptedPacket = new EncryptedPacket { Iv = _aes.GenerateRandomNumber(12) };

            (byte[] ciphereText, byte[] tag) encrypted = _aes.Encrypt(original, sessionKey, encryptedPacket.Iv, null);

            encryptedPacket.EncryptedData = encrypted.ciphereText;
            encryptedPacket.Tag = encrypted.tag;
            encryptedPacket.EncryptedSessionKey = rsaParams.EncryptData(sessionKey);
         
            return encryptedPacket;
        }

        public byte[] DecryptData(EncryptedPacket encryptedPacket, RSAWithRSAParameterKey rsaParams)
        {
            var decryptedSessionKey = rsaParams.DecryptData(encryptedPacket.EncryptedSessionKey);

            
            var decryptedData = _aes.Decrypt(encryptedPacket.EncryptedData, decryptedSessionKey,
                                             encryptedPacket.Iv, encryptedPacket.Tag, null);

            return decryptedData;
        }
    }
}
