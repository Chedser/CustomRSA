using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace RSA
{
    public class RSAAlgorithm
    {
        private RandomNumberGenerator rng = RandomNumberGenerator.Create();
        private Random random = new Random();

        // Параметры RSA
        public BigInteger P { get; private set; }
        public BigInteger Q { get; private set; }
        public BigInteger N { get; private set; }
        public BigInteger Lambda { get; private set; }
        public BigInteger E { get; private set; }
        public BigInteger D { get; private set; }

        // Флаг, что ключи сгенерированы
        public bool KeysGenerated { get; private set; } = false;

        // Генерация ключей
        public void GenerateKeys(int bitSize)
        {
            try
            {
                // Генерируем простые числа с разной битностью
                // p = b-1 бит, q = b бит
                int pBits = bitSize - 1;
                int qBits = bitSize;

                P = GenerateLargePrime(pBits);
                Q = GenerateLargePrime(qBits);

                // Вычисляем n = p * q
                N = P * Q;

                // Вычисляем λ(n) = lcm(p-1, q-1)
                BigInteger pMinus1 = P - 1;
                BigInteger qMinus1 = Q - 1;
                Lambda = Lcm(pMinus1, qMinus1);

                // Используем фиксированное значение e = 65537
                E = 65537;

                // Проверяем, что e и λ(n) взаимно просты
                if (BigInteger.GreatestCommonDivisor(E, Lambda) != 1)
                {
                    throw new Exception("Выбранное e не взаимно просто с λ(n). Попробуйте сгенерировать ключи заново.");
                }

                // Вычисляем d = e^(-1) mod λ(n)
                D = ModInverse(E, Lambda);

                KeysGenerated = true;
            }
            catch
            {
                KeysGenerated = false;
                throw;
            }
        }

        // Шифрование сообщения
        public BigInteger Encrypt(BigInteger message)
        {
            if (!KeysGenerated)
                throw new InvalidOperationException("Ключи не сгенерированы");

            // Проверяем, что сообщение меньше n
            if (message >= N)
                throw new ArgumentException($"Сообщение должно быть меньше модуля n ({N})");

            // c = m^e mod n
            return BigInteger.ModPow(message, E, N);
        }

        // Дешифрование сообщения
        public BigInteger Decrypt(BigInteger ciphertext)
        {
            if (!KeysGenerated)
                throw new InvalidOperationException("Ключи не сгенерированы");

            // m = c^d mod n
            return BigInteger.ModPow(ciphertext, D, N);
        }

        // Создание подписи
        public BigInteger Sign(BigInteger hash)
        {
            if (!KeysGenerated)
                throw new InvalidOperationException("Ключи не сгенерированы");

            // s = hash^d mod n
            return BigInteger.ModPow(hash, D, N);
        }

        // Проверка подписи
        public bool VerifySignature(BigInteger hash, BigInteger signature)
        {
            if (!KeysGenerated)
                throw new InvalidOperationException("Ключи не сгенерированы");

            // Проверяем: signature^e mod n == hash
            BigInteger verifiedHash = BigInteger.ModPow(signature, E, N);
            return verifiedHash == hash;
        }

        // Преобразование текста в число (с padding)
        public static BigInteger TextToBigInteger(string text)
        {
            if (string.IsNullOrEmpty(text))
                text = " ";

            byte[] bytes = Encoding.UTF8.GetBytes(text);

            // Для little-endian добавляем 0x00 в КОНЕЦ массива
            byte[] bytesForBigInteger = new byte[bytes.Length + 1];
            Array.Copy(bytes, 0, bytesForBigInteger, 0, bytes.Length);

            return new BigInteger(bytesForBigInteger);
        }

        // Преобразование числа в текст
        public static string BigIntegerToText(BigInteger number)
        {
            byte[] bytes = number.ToByteArray();

            // Удаляем последний байт если это padding
            if (bytes.Length > 0 && bytes[bytes.Length - 1] == 0)
            {
                bytes = bytes.Take(bytes.Length - 1).ToArray();
            }

            // Проверяем, что массив байт можно преобразовать в UTF8 строку
            if (bytes.Length > 0)
            {
                return Encoding.UTF8.GetString(bytes);
            }

            return string.Empty;
        }

        // Проверка, является ли строка валидным текстом
        public static bool IsValidText(string text)
        {
            return text.All(c => c >= 32 && c <= 126 || c == '\n' || c == '\r' || c == '\t');
        }

        // Генерация большого простого числа заданной битности
        private BigInteger GenerateLargePrime(int bits)
        {
            if (bits < 2)
                bits = 2;

            byte[] bytes = new byte[bits / 8 + 1];
            BigInteger number;

            do
            {
                rng.GetBytes(bytes);
                int byteIndex = bytes.Length - 1;
                bytes[byteIndex] = 0;

                for (int i = 0; i < bits % 8; i++)
                {
                    bytes[byteIndex] |= (byte)(1 << i);
                }

                number = new BigInteger(bytes);

                if (number < 0)
                    number = -number;
                if (number % 2 == 0)
                    number++;

            } while (!IsProbablePrime(number));

            return number;
        }

        // Проверка числа на простоту (тест Миллера-Рабина)
        private bool IsProbablePrime(BigInteger n, int k = 10)
        {
            if (n < 2) return false;
            if (n == 2 || n == 3) return true;
            if (n % 2 == 0) return false;

            BigInteger d = n - 1;
            int s = 0;
            while (d % 2 == 0)
            {
                d /= 2;
                s++;
            }

            for (int i = 0; i < k; i++)
            {
                BigInteger a = RandomInRange(2, n - 2);
                BigInteger x = BigInteger.ModPow(a, d, n);

                if (x == 1 || x == n - 1)
                    continue;

                bool composite = true;
                for (int r = 0; r < s - 1; r++)
                {
                    x = BigInteger.ModPow(x, 2, n);
                    if (x == n - 1)
                    {
                        composite = false;
                        break;
                    }
                }

                if (composite)
                    return false;
            }

            return true;
        }

        // Генерация случайного числа в диапазоне
        private BigInteger RandomInRange(BigInteger min, BigInteger max)
        {
            if (min > max)
                throw new ArgumentException("min должно быть меньше или равно max");

            BigInteger range = max - min + 1;
            byte[] bytes = range.ToByteArray();
            BigInteger result;

            do
            {
                rng.GetBytes(bytes);
                bytes[bytes.Length - 1] &= 0x7F;
                result = new BigInteger(bytes);
            } while (result < min || result > max);

            return result;
        }

        // Наименьшее общее кратное
        private BigInteger Lcm(BigInteger a, BigInteger b)
        {
            return (a / BigInteger.GreatestCommonDivisor(a, b)) * b;
        }

        // Модульное обратное число
        private BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            BigInteger m0 = m;
            BigInteger y = 0, x = 1;

            if (m == 1)
                return 0;

            while (a > 1)
            {
                BigInteger q = a / m;
                BigInteger t = m;

                m = a % m;
                a = t;
                t = y;

                y = x - q * y;
                x = t;
            }

            if (x < 0)
                x += m0;

            return x;
        }
    }
}