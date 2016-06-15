#undef DEBUG

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace XorCypherTest
{
    class Program
    {
        const int DIGESTSZ = 8;

        static void PrintBytes(byte[] arr)
        {
            foreach (byte b in arr)
                Console.Write((char)b + "\t");
            Console.WriteLine();

            foreach (byte b in arr)
                Console.Write(b + "\t");
            Console.WriteLine();
        }

        static void Cypher (ref byte[] arr, byte[] cypher)
        {
            for (int ci = cypher.Length-1; ci > 0; ci--)
            {
                for (int i = 0; i < arr.Length; i++)
                {
                    arr[i] ^= (byte)(cypher[ci] - (cypher.Length * i * i) % 0xFF);

                    for (int j = 0; j < cypher.Length; j++)
                        arr[i] = (byte)(arr[i] ^ (cypher[j] * i + i * (cypher[ci] * j)));
                }
            }
        }

        static byte[] Encrypt(byte[] arr, byte[] cypher)
        {
            byte[] innerCyph = new byte[DIGESTSZ];
            new RNGCryptoServiceProvider().GetBytes(innerCyph);
            Console.WriteLine("\n\n Inner (super secret) Cypher:\n");
            PrintBytes(innerCyph);

            // Encrypt inner message with inner cyph
            Cypher(ref arr, innerCyph);

            byte[] payload = new byte[arr.Length + DIGESTSZ];
            innerCyph.CopyTo(payload, 0);
            arr.CopyTo(payload, DIGESTSZ);
#if DEBUG
            PrintBytes(arr);
            PrintBytes(payload);
#endif
            // Encrypt payload package with OUTER cypher
            Cypher(ref payload, cypher);

            return payload;
        }

        static byte[] Decrypt(byte[] arr, byte[] cypher)
        {
            // Decrypt with outer cyph
            Cypher(ref arr, cypher);
            //PrintBytes(arr);

            byte[] decyph = new byte[arr.Length - DIGESTSZ];
            byte[] innerCyph = new byte[DIGESTSZ];
            Buffer.BlockCopy(arr, 0, innerCyph, 0, DIGESTSZ);
            Buffer.BlockCopy(arr, DIGESTSZ, decyph, 0, decyph.Length);
            //PrintBytes(arr);

            // Decrypt inner block with inner cyph
            Cypher(ref decyph, innerCyph);

            return decyph;
        }

        static void Main(string[] args)
        {
            Console.Write("Enter a string to encode: ");
            string txt = Console.ReadLine();
            byte[] tbytes = ASCIIEncoding.ASCII.GetBytes(txt);
            PrintBytes(tbytes);

            byte[] cypher = new byte[] { 0x48, 0x12, 0xDE, 0x15, 0x01, 0xF9, 0xF9, 0xF9, 0x02, 0x51, 0x7C, 0xEE, 0xAE };
            for (;;)
            {
                Console.WriteLine("Enter a cypher, or RETURN for default.\n\t(Hex, longer is better!)");
                string strCypher = Console.ReadLine().Replace(" ", "");

                if(strCypher.Length % 2 != 0)
                    continue;

                try {
                    if (strCypher != string.Empty)
                        cypher = StringToByteArray(strCypher);
                } catch { continue; }
                break;
            }

            Console.WriteLine("OK\n\n (Outer-Packet) Cypher:\n");
            PrintBytes(cypher);

            byte[] encrypted = Encrypt(tbytes, cypher);
            Console.WriteLine("\n\n Encrypted:\n");
            PrintBytes(encrypted);

            byte[] decrypted = Decrypt(encrypted, cypher);
            Console.WriteLine("\n\n Decrypted:\n");
            PrintBytes(decrypted);

            Console.ReadLine();
        }

        /// <summary>
        /// Fun hex string to byte utility using LINQ
        /// by JaredPar:
        /// http://stackoverflow.com/a/321404/5571426
        /// </summary>
        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}
