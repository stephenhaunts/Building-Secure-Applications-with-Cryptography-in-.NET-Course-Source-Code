using System;
using System.Security.Cryptography;
using System.Text;

namespace Pluralsight.HybridWithIntegrityAndSignatureGCM
{
	public class NewDigitalSignature
    {
        private RSA rsa; 
 
        public NewDigitalSignature()
        {
            rsa = RSA.Create(2048);
        }


        public byte[] SignData(byte[] dataToSign)
        {
            return (rsa.SignHash(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        public bool VerifySignature(byte[] signature, byte[] hashOfDataToSign)
        {
            return rsa.VerifyHash(hashOfDataToSign, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);            
        }

        public byte[] ExportPrivateKey(int numberOfIterations, string password)
        {
            byte[] encryptedPrivateKey = new byte[2000];
           
            PbeParameters keyParams = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, numberOfIterations);  
            encryptedPrivateKey = rsa.ExportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(password), keyParams);

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
