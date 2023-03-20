using System;
using System.Security.Cryptography;
using System.Text;

internal static class Encryption
{
    internal static string Encrypt(string key, string plaintext, bool gzip = false)
    {
        return Encrypt(key, Encoding.UTF8.GetBytes(plaintext), gzip);
    }

    internal static string Encrypt(string key, byte[] plaintext, bool gzip = false)
    {
        if (gzip)
            plaintext = Utils.Compress(plaintext);

        try
        {
            var algorithm = CreateAlgorithm(key, null);
            var cipherText = algorithm.CreateEncryptor().TransformFinalBlock(plaintext, 0, plaintext.Length);
            return Convert.ToBase64String(Utils.Combine(algorithm.IV, cipherText));
        }
        catch
        {
            var cipher = CreateAlgorithm(key, null, false);
            var cipherText = cipher.CreateEncryptor().TransformFinalBlock(plaintext, 0, plaintext.Length);
            return Convert.ToBase64String(Utils.Combine(cipher.IV, cipherText));
        }
    }

    private static byte[] Decrypt(string key, byte[] ciphertext)
    {
        var iv = new byte[16];
        Array.Copy(ciphertext, iv, 16);
        try
        {
            var cipher = CreateAlgorithm(key, Convert.ToBase64String(iv));
            return cipher.CreateDecryptor().TransformFinalBlock(ciphertext, 16, ciphertext.Length - 16);
        }
        catch
        {
            var cipher = CreateAlgorithm(key, Convert.ToBase64String(iv), false);
            return cipher.CreateDecryptor().TransformFinalBlock(ciphertext, 16, ciphertext.Length - 16);
        }
        finally
        {
            Array.Clear(ciphertext, 0, ciphertext.Length);
            Array.Clear(iv, 0, 16);
        }
    }

    internal static byte[] Decrypt(string key, string base64EncodedCiphertext)
    {
        var ciphertext = Convert.FromBase64String(base64EncodedCiphertext);
        return Decrypt(key, ciphertext);
    }

    private static SymmetricAlgorithm CreateAlgorithm(string key, string iv, bool useRijndael = true)
    {
        SymmetricAlgorithm algorithm;
        if (useRijndael)
            algorithm = new RijndaelManaged();
        else
            algorithm = new AesCryptoServiceProvider();

        algorithm.Mode = CipherMode.CBC;
        algorithm.Padding = PaddingMode.Zeros;
        algorithm.BlockSize = 128;
        algorithm.KeySize = 256;

        if (null != iv)
            algorithm.IV = Convert.FromBase64String(iv);
        else
            algorithm.GenerateIV();

        if (null != key)
            algorithm.Key = Convert.FromBase64String(key);

        return algorithm;
    }
}