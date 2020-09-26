using Newtonsoft.Json;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Encrypt
{
    public class AesEncryption
    {
        #region Properties


        /// <summary>
        /// For initial authentication it's APISecretKey
        /// After authenticated - Session Key
        /// </summary>
        byte[] Key;


        /// <summary>
        /// Keep IV from EncryptStringToBytes to return in sIV
        /// </summary>
        byte[] IV;


        /// <summary>
        /// Return IV from EncryptStringToBytes
        /// </summary>
        public string sIV
        {
            get
            {
                if (IV == null)
                    return null;

                return Convert.ToBase64String(IV);
            }
        }


        #endregion Properties


        #region Methods


        /// <summary>
        /// API key is HEX, but Session key is base64
        /// For initial authentication it's APISecretKey
        /// After authenticated - Session Key
        /// </summary>
        /// <param name="base64Key">Session Key</param>
        /// <param name="APISecretKey">APISecretKey (HEX)</param>
        /// <param name="APIAuthKey">APISecretKey</param>
        public AesEncryption(string base64Key = null, string APISecretKey = null, string APIAuthKey = null)
        {
            if (base64Key != null)
            {
                this.Key = Convert.FromBase64String(base64Key);
            }
            else
            {
                this.Key = StringToByteArray(APISecretKey);
            }

            // Calculate HMAC-SHA256 using API Auth Key
            this.APIAuthKey = APIAuthKey;
        }


        /// <summary>
        /// Convert HEX string to byte[]
        /// </summary>
        /// <param name="hex"></param>
        /// <returns></returns>
        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }


        #endregion Methods


        #region HMAC

        public string APIAuthKey;

        /// <summary>
        /// The MAC to calculate is a HMAC-SHA256 using API Auth Key
        /// </summary>
        /// <param name="paylaoad"></param>
        /// <param name="Key"></param>
        /// <returns></returns>
        public string StringHash(string paylaoad)
        {
            return StringHash(paylaoad, APIAuthKey);
        }

        static public byte[] ByteHash(string paylaoad, byte[] Key)
        {
            HMACSHA256 hmac = new HMACSHA256(Key);
            byte[] buffer = Encoding.ASCII.GetBytes(paylaoad);
            return hmac.ComputeHash(buffer);
        }

        static public string StringHash(string paylaoad, string hexKey)
        {
            byte[] Key = StringToByteArray(hexKey);
            byte[] bHash = ByteHash(paylaoad, Key);
            return Convert.ToBase64String(bHash);
        }


        #endregion HMAC


        #region Encrypt


        /// <summary>
        /// 
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="Key"></param>
        /// <param name="IV"></param>
        /// <returns>Return the encrypted bytes from the memory stream</returns>
        byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] iv = null)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");

            // Create an AesCryptoServiceProvider object
            // with the specified key and IV.
            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
            {
                aesAlg.Key = Key;

                if (iv != null)
                    aesAlg.IV = iv;
                else
                    aesAlg.GenerateIV();

                this.IV = aesAlg.IV;

                Console.WriteLine($"Encrypt: {plainText}, Key: {Convert.ToBase64String(Key)}, IV: {Convert.ToBase64String(IV)}");

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        return msEncrypt.ToArray();
                    }
                }
            }
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="sKey"></param>
        /// <param name="sIV">optional, mostly for testing</param>
        /// <returns></returns>
        public string EncryptStringToBytes(string plainText, string sKey = null, string sIV = null)
        {
            if(!String.IsNullOrEmpty(sKey))
                Key = StringToByteArray(sKey);

            byte[] iv = (!String.IsNullOrEmpty(sIV))? Convert.FromBase64String(sIV) : null;
            byte[] encrypted = EncryptStringToBytes(plainText, Key, iv);

            return Convert.ToBase64String(encrypted);
        }


        #endregion Encrypt


        #region Decrypt


        /// <summary>
        /// 
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="IV"></param>
        /// <returns></returns>
        public string DecryptStringFromBytes(string cipherText, string IV)
        {
            byte[] byteCipherText = Convert.FromBase64String(cipherText);
            byte[] byteIV = Convert.FromBase64String(IV);

            return DecryptStringFromBytes_Aes(byteCipherText, this.Key, byteIV);
        }


        /// <summary>
        /// Note: n exception handling
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="cipherText"></param>
        /// <param name="IV"></param>
        /// <returns></returns>
        public T DecryptStringFromBytes<T>(string cipherText, string IV)
        {
            string json = DecryptStringFromBytes(cipherText, IV);
            Console.WriteLine($"Decrypted payload: {json}, IV: '{IV}'");
            return JsonConvert.DeserializeObject<T>(json);
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="Key"></param>
        /// <param name="IV"></param>
        /// <returns></returns>
        public static string DecryptStringFromBytes_Aes(string cipherText, string Key, string IV)
        {
            byte[] byteCipherText = Convert.FromBase64String(cipherText);
            byte[] byteIV = Convert.FromBase64String(IV);
            byte[] byteKey = StringToByteArray(Key);

            return DecryptStringFromBytes_Aes(byteCipherText, byteKey, byteIV);
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="Key"></param>
        /// <param name="IV"></param>
        /// <returns></returns>
        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Create an AesCryptoServiceProvider object
            // with the specified key and IV.
            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }

        #endregion Decrypt
    }
}