using System;
using System.Security.Cryptography;
using System.Text;

namespace Pluralsight.DigitalSignature
{
	class NewDigitalSignature
    {
        private RSA rsa; 
 
        public NewDigitalSignature()
        {
            rsa = RSA.Create(2048);
        }

        public static byte[] ComputeHashSha256(byte[] toBeHashed)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(toBeHashed);
            }
        }

        public (byte[], byte[]) SignData(byte[] dataToSign)
        {
            byte[] hashOfDataToSign = ComputeHashSha256(dataToSign);

            return (rsa.SignHash(hashOfDataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), hashOfDataToSign);
        }

        public bool VerifySignature(byte[] signature, byte[] hashOfDataToSign)
        {
            return rsa.VerifyHash(hashOfDataToSign, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);            
        }

        public byte[] ExportPrivateKey(int numberOfIterations, string password)
        {
            byte[] encryptedPrivateKey = new byte[2000];
           
            PbeParameters keyParams = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, numberOfIterations);  
            var arraySpan = new Span<byte>(encryptedPrivateKey);
            rsa.TryExportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(password), keyParams, arraySpan, out _);

            return encryptedPrivateKey;
        }

        public void ImportEncryptedPrivateKey(byte[] encryptedKey, string password)
        {
            rsa.ImportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(password), encryptedKey, out _);
        }

        public byte[] ExportPublicKey()
        {
            return rsa.ExportRSAPublicKey();
        }

        public void ImportPublicKey(byte[] publicKey)
        {
            rsa.ImportRSAPublicKey(publicKey, out _);
        }
    }
}
