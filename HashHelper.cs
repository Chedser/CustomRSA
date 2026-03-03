using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace RSA
{
    public static class HashHelper
    {
        // Вычисление хеша
        public static byte[] ComputeHash(byte[] data, string algorithm)
        {
            using (HashAlgorithm hashAlgorithm = GetHashAlgorithm(algorithm))
            {
                return hashAlgorithm.ComputeHash(data);
            }
        }

        // Получение алгоритма хеширования по имени
        private static HashAlgorithm GetHashAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case "SHA1": return SHA1.Create();
                case "SHA256": return SHA256.Create();
                case "SHA384": return SHA384.Create();
                case "SHA512": return SHA512.Create();
                default: return SHA256.Create();
            }
        }

        // Преобразование ID пользователя в байты
        public static byte[] UserIdToBytes(int userId)
        {
            byte[] hash = BitConverter.GetBytes(userId);
            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(hash);
            }
            return hash;
        }

        // Получение отображаемой строки для хеша
        public static string GetHashDisplay(byte[] hash, string algorithm)
        {
            if (algorithm == "USER_ID")
            {
                int userId = BitConverter.ToInt32(hash, 0);
                return $"ID пользователя: {userId}";
            }
            else
            {
                return $"Хеш ({algorithm}): {BitConverter.ToString(hash).Replace("-", "").ToLower()}";
            }
        }

        // Преобразование хеша в BigInteger с padding
        public static BigInteger HashToBigInteger(byte[] hash, BigInteger modulus)
        {
            byte[] hashWithPadding = new byte[hash.Length + 1];
            Array.Copy(hash, 0, hashWithPadding, 0, hash.Length);
            return new BigInteger(hashWithPadding) % modulus;
        }
    }
}