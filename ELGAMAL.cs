using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        /// 

        private static int Power(int x, int y, int z)
        {
            //Math.Pow() => Overflow
            int res = 1;
            while(y > 0)
            {
                res = (x * res) % z;
                y--;
            }
            return res;
        }

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            /* Encryption
             * C1 = (alpha^k) mod q

             * K = (y^k) mod q
             * C2 = (KM) mod 1
             */

            int K = Power(y ,k, q);

            List<long> c = new List<long>(2)
            {
                (long)Power(alpha, k, q),
                (long)(K * m % q)
            };

            return c;
        }
     
        public int Decrypt(int c1, int c2, int x, int q)
        {
            /* Decryption
             * K^-1 = (C1)^(q - 1 - x) mod q
             * M = (C2 * K^-1) mod 1
             */
            int K_1 = Power(c1, q - 1 - x, q);
            int m = (int)(c2 * K_1 % q);
            return m;
        }
    }
}
