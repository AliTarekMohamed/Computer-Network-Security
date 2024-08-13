using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public int power(int f, int s, int sf)
        {
            //Math.Pow() => Overflow
            int res = 1;
            while (s > 0)
            {
                res = f * res % sf;
                s--;
            }
            return res;
        }

        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int ya = power(alpha, xa, q);
            int yb = power(alpha, xb, q);

            List<int> keys = new List<int>(2)
            {
                power(yb, xa, q),
                power(ya, xb, q)
            };

            return keys;
        }
    }
}