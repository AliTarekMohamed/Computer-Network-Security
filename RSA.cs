using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace SecurityLibrary.RSA
{
    public class RSA
    {
        private int Power(int x, int y, int z)
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

        //Extended Euclid
        private int GetMultiplicativeInverse(int number, int baseN)
        {
            int A1 = 1, A2 = 0, A3 = baseN;
            int B1 = 0, B2 = 1, B3 = number;

            while (B3 != 1 && B3 != 0)
            {
                int Q = A3 / B3;
                int temp = A1;
                A1 = B1;
                B1 = temp - Q * B1;
                temp = A2;
                A2 = B2;
                B2 = temp - Q * B2;
                temp = A3;
                A3 = B3;
                B3 = temp - Q * B3;  // as the same temp - Q * B3
            }
            int inverse = (B2 % baseN + baseN) % baseN;
            if (B3 == 1)
            {
                return inverse;
            }
            else
            {
                return -1;
            }
        }

        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            return Power(M, e, n);
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int euler = (p - 1) * (q - 1);

            int d = GetMultiplicativeInverse(e, euler);

            return Power(C, d, n);
        }
    }
}
