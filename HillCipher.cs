using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int num = 2;
            int[,] plainmatrix = convertToMatrix(plainText, num);
            int[,] ciphermatrix = convertToMatrix(cipherText, num);
            int[,] temp = new int[2,2];
            int[,] temp2 = new int[2,2];
            bool found = false;
            for (int i = 0; i < (plainmatrix.Length/2); i++)
            {
                if (num == 2)
                {
                    temp[0, 0] = plainmatrix[0, i];
                    temp[1, 0] = plainmatrix[1, i]; 
                    temp2[0, 0] = ciphermatrix[0, i];
                    temp2[1, 0] = ciphermatrix[1, i];
                    for (int j = 0; j < (plainmatrix.Length)/2; j++) {
                        if (i == j) continue;
                        temp[0, 1] = plainmatrix[0, j];
                        temp[1, 1] = plainmatrix[1, j];
                        temp2[0, 1] = ciphermatrix[0, j];
                        temp2[1, 1] = ciphermatrix[1, j];
                        int det = calcDet2x2(temp);
                        bool check = checkdet(det);
                        if (!check)
                        {
                            continue;
                        }
                        int b = getB(det);
                        temp = inverse2x2(temp, b);
                        found = true;
                        break;
                    }

                }
                if (found)
                    break;
            }
            if(!found)
                throw new InvalidAnlysisException();
            int[,] keymatrix = matrixmlt(temp2, temp);
            List<int> result = new List<int>();
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    result.Add(keymatrix[i, j] % 26);
                }
            }
            return result;
        }
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int num = Convert.ToInt32(Math.Sqrt(key.Count));
            int[,] keymatrix = convertkeyToMatrix(key, num);
            int[,] ciphermatrix = convertToMatrix(cipherText, num);
            if (num == 2)
            {
                int det = calcDet2x2(keymatrix);

                bool check = checkdet(det);

                if (!check)
                {
                    throw new NotImplementedException();
                }
                int b = getB(det);
                keymatrix = inverse2x2(keymatrix, b);

            }
            else if (num == 3)
            {
                int det = calcDet3x3(keymatrix);
                bool check = checkdet(det);
                if (!check)
                {
                    throw new NotImplementedException();
                }
                int b = getB(det);
                keymatrix = inverse3x3(keymatrix, b);
            }
            int[,] plainmatrix = matrixmlt(keymatrix, ciphermatrix);
            List<int> result = new List<int>();
            for (int i = 0; i < plainmatrix.GetLength(1); i++)
            {
                for (int j = 0; j < plainmatrix.GetLength(0); j++)
                {
                    result.Add(plainmatrix[j, i] % 26);

                }
            }
            return result;
            //throw new NotImplementedException();
            // throw new NotImplementedException();
        }
        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int num = Convert.ToInt32(Math.Sqrt(key.Count));
            int[,] keymatrix = convertkeyToMatrix(key, num);
            int[,] plainmatrix = convertToMatrix(plainText, num);
            int[,] ciphermatrix = matrixmlt(keymatrix, plainmatrix);
            List<int> result = new List<int>();
            for (int i = 0; i < ciphermatrix.GetLength(1); i++)
            {
                for (int j = 0; j < ciphermatrix.GetLength(0); j++)
                {
                    result.Add(ciphermatrix[j, i] % 26);
                }
            }
            return result;
        }
        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }


        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {

            int num = Convert.ToInt32(Math.Sqrt(plain3.Count));
            int[,] plainmatrix = convertToMatrix(plain3, num);
            int[,] ciphermatrix = convertToMatrix(cipher3, num);


            if (num == 3)
            {
                int det = calcDet3x3(plainmatrix);
                bool check = checkdet(det);
                if (!check)
                {
                    throw new NotImplementedException();
                }
                int b = getB(det);
                plainmatrix = inverse3x3(plainmatrix, b);
            }
            int[,] key = matrixmlt(ciphermatrix, plainmatrix);
            List<int> result = new List<int>();
            for (int i = 0; i < key.GetLength(0); i++)
            {
                for (int j = 0; j < key.GetLength(1); j++)
                {
                    result.Add(key[i, j] % 26);

                }
            }
            return result;
            throw new NotImplementedException();
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }

        public static Int32 calcDet2x2(int[,] matrix)
        {
            int x = (matrix[0, 0] * matrix[1, 1]) - (matrix[0, 1] * matrix[1, 0]);
            x = x % 26;
            while (x < 0)
            {
                x = x + 26;
            }

            return x;
        }
        public static Int32 calcDet3x3(int[,] matrix)
        {
            int det = 0;
            for (int i = 0; i < 3; i++)
            {
                int sub = calcDet2x2(createsubmatrix(matrix, 0, i));
                det = det + (Convert.ToInt32(Math.Pow(-1, i)) * matrix[0, i] * sub);
            }
            det = det % 26;
            while (det < 0)
            {
                det = det + 26;
            }

            return det;
        }
        public static int[,] createsubmatrix(int[,] matrix, int row, int col)
        {
            int[,] submatrix = new int[2, 2];
            int newrow = 0, newcol = 0;
            for (int i = 0; i < matrix.GetLength(0); i++)
            {
                for (int j = 0; j < matrix.GetLength(1); j++)
                {
                    if ((i != row) && (j != col))
                    {
                        if (newcol <= 1)
                        {
                            submatrix[newrow, newcol] = matrix[i, j];
                            newcol++;
                            if (newcol == 2)
                            {
                                newcol = 0;
                                newrow++;
                            }
                        }
                    }
                }
            }

            return submatrix;
        }

        public static int euclid(int a, int b)
        {
            if (b == 0)
                return a;
            else
                return euclid(b, a % b);
        }
        public static bool checkdet(int det)
        {

            bool check = false;
            if (det > 0 && det < 26)
            {
                if (euclid(26, det) == 1)
                {
                    if (getB(det) != -1)
                    {
                        check = true;
                    }
                }
            }
            return check;
        }
        public static int getB(int det)
        {
            int c = 26 - det;
            for (int j = 1; j <= 26; j++)
            {
                if ((c * j) % 26 == 1)
                {
                    return 26 - j;
                }

            }
            return -1;
        }

        public static int[,] inverse2x2(int[,] matrix, int b)
        {
            int[,] res = new int[matrix.GetLength(0), matrix.GetLength(1)];
            res[0, 0] = (b * matrix[1, 1]) % 26;
            res[0, 1] = (-1 * matrix[0, 1] * b) % 26;
            res[1, 0] = (-1 * matrix[1, 0] * b) % 26;
            res[1, 1] = (b * matrix[0, 0]) % 26;
            while (res[0, 1] < 0)
            {
                res[0, 1] = res[0, 1] + 26;
            }
            while (res[1, 0] < 0)
            {
                res[1, 0] = res[1, 0] + 26;
            }

            return res;
        }

        public static int[,] inverse3x3(int[,] matrix, int b)
        {
            int[,] res = new int[matrix.GetLength(0), matrix.GetLength(1)];
            for (int i = 0; i < matrix.GetLength(0); i++)
            {
                for (int j = 0; j < matrix.GetLength(1); j++)
                {
                    int sub = calcDet2x2(createsubmatrix(matrix, i, j));
                    res[i, j] = b * (Convert.ToInt32(Math.Pow(-1, i + j)) * sub);
                    res[i, j] = res[i, j] % 26;
                    while (res[i, j] < 0)
                    {
                        res[i, j] = res[i, j] + 26;
                    }
                }

            }
            int[,] res1 = new int[matrix.GetLength(0), matrix.GetLength(1)];
            for (int i = 0; i < matrix.GetLength(0); i++)
            {
                for (int j = 0; j < matrix.GetLength(1); j++)
                {
                    res1[i, j] = res[j, i];
                }

            }
            return res1;
        }
        public static int[,] convertkeyToMatrix(List<int> key, int num)
        {
            int[,] result = new int[num, num];
            for (int i = 0; i < num; i++)
            {
                for (int j = 0; j < num; j++)
                {
                    result[i, j] = key[(i * num) + j];
                }
            }

            return result;
        }
        public static int[,] convertToMatrix(List<int> arr, int num)
        {
            int[,] result = new int[num, (arr.Count / num)];
            for (int i = 0; i < num; i++)
            {
                for (int j = 0; j < (arr.Count / num); j++)
                {
                    result[i, j] = arr[(j * num) + i];

                }
            }

            return result;
        }

        public static int[,] matrixmlt(int[,] matrix1, int[,] matrix2)
        {
            int[,] result = new int[matrix1.GetLength(0), matrix2.GetLength(1)];
            for (int i = 0; i < result.GetLength(0); i++)
            {
                for (int j = 0; j < result.GetLength(1); j++)
                {
                    for (int k = 0; k < matrix1.GetLength(1); k++)
                    {
                        result[i, j] += matrix1[i, k] * matrix2[k, j];
                    }
                }
            }


            return result;
        }
    }
}

