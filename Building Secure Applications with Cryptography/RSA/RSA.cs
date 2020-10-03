using System;
using System.Security.Cryptography;
using System.Text;

namespace Pluralsight.Asymetric
{
	class NewRSA
    {
        static byte[] publicKey;
        static byte[] privateKey;

        static byte[] encryptedPrivateKey = new byte[2000];
        static string privateKeyPassword = "M3g4C0mpl3xP455w0rd!";    

        //static void Main(string[] args)
        //{
        //    CreateKeys();
        //    SimpleEncryptDecrypt();

        //    CreateEncryptedKeys();
        //    SimpleEncryptDecryptEncryptedPrivate();
        //}

        private static void SimpleEncryptDecrypt()
        {
            var rsa = RSA.Create(2048);

            rsa.ImportRSAPublicKey(publicKey, out _);
            rsa.ImportRSAPrivateKey(privateKey, out _);

            string toEncrypt = "Mary had a little Lamb";

            byte[] encrypted = rsa.Encrypt(Encoding.UTF8.GetBytes(toEncrypt), RSAEncryptionPadding.OaepSHA256);
            byte[] decrypted = rsa.Decrypt(encrypted, RSAEncryptionPadding.OaepSHA256);

            string decryptedString = Encoding.UTF8.GetString(decrypted);
            Console.WriteLine("Decrypted = " + decryptedString);
        }

        private static void SimpleEncryptDecryptEncryptedPrivate()
        {
            var rsa = RSA.Create(2048);

            rsa.ImportRSAPublicKey(publicKey, out _);
            rsa.ImportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(privateKeyPassword), encryptedPrivateKey, out _);

            string toEncrypt = "Mary had a little Lamb";

            byte[] encrypted = rsa.Encrypt(Encoding.UTF8.GetBytes(toEncrypt), RSAEncryptionPadding.OaepSHA256);
            byte[] decrypted = rsa.Decrypt(encrypted, RSAEncryptionPadding.OaepSHA256);

            string decryptedString = Encoding.UTF8.GetString(decrypted);
            Console.WriteLine("Decrypted = " + decryptedString);
        }

        private static void CreateKeys()
        {
            var rsa = RSA.Create(2048);

            publicKey = rsa.ExportRSAPublicKey();
            privateKey = rsa.ExportRSAPrivateKey();
        }

        private static void CreateEncryptedKeys()
        {
            var rsa = RSA.Create(2048);

            PbeParameters keyParams = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100000);

            publicKey = rsa.ExportRSAPublicKey();

            var arraySpan = new Span<byte>(encryptedPrivateKey);
            bool privateKeyExportResult = rsa.TryExportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(privateKeyPassword), keyParams, arraySpan, out _);
            
        }
    }
}
