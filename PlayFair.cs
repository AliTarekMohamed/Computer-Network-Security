using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            char[,] grid = GenerateGrid(key);

            string cleanCipherText = cipherText.ToUpper();
            cleanCipherText.Replace('J', 'I');
            StringBuilder plainText = new StringBuilder();
            for (int i = 0; i < cleanCipherText.Length; i += 2)
            {
                char a = cleanCipherText[i];
                char b = cleanCipherText[i + 1];
                int aRow, aCol, bRow, bCol;
                GetPositions(grid, a, out aRow, out aCol);
                GetPositions(grid, b, out bRow, out bCol);
                if (aRow == bRow)
                {
                    plainText.Append(grid[aRow, (aCol + 4) % 5]);
                    plainText.Append(grid[bRow, (bCol + 4) % 5]);
                }
                else if (aCol == bCol)
                {
                    plainText.Append(grid[(aRow + 4) % 5, aCol]);
                    plainText.Append(grid[(bRow + 4) % 5, bCol]);
                }
                else
                {
                    plainText.Append(grid[aRow, bCol]);
                    plainText.Append(grid[bRow, aCol]);
                }
            }
            StringBuilder v = new StringBuilder();
            v.Append(plainText[0]);

            for (int i = 1; i < plainText.Length - 1; i++)
            {
                if (!(plainText[i] == 'X' && plainText[i - 1] == plainText[i + 1] && i % 2 != 0))
                {
                    v.Append(plainText[i]);

                }
            }
            if (!(plainText[plainText.Length - 1] == 'X'))
            {
                v.Append(plainText[plainText.Length - 1]);

            }
            string o = v.ToString();

            return (o.ToLower());
        }

        private char[,] GenerateGrid(string key)
        {
            string cleanKey = new string(key.ToUpper().Distinct().ToArray());
            char[,] grid = new char[5, 5];
            cleanKey.Replace('J', 'I');
            string alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            string keyPlusAlphabet = cleanKey + alphabet;

            string Lastkey = new string(keyPlusAlphabet.ToUpper().Distinct().ToArray());

            string str = Lastkey.Substring(0, 25);
            Console.WriteLine(str);

            int index = 0;
            for (int row = 0; row < 5; row++)
            {
                for (int col = 0; col < 5; col++)
                {
                    grid[row, col] = Lastkey[index];
                    index++;
                }
            }
            return grid;
        }
        private void GetPositions(char[,] grid, char letter, out int row, out int col)
        {
            row = -1; col = -1;
            for (int r = 0; r < 5; r++)
            {
                for (int c = 0; c < 5; c++)
                {
                    if (grid[r, c] == letter)
                    {
                        row = r; col = c;
                        break;
                    }
                }
            }
        }

        public string Encrypt(string plainText, string key)
        {

            char[,] matrix = getMatrix(key);
            string ciphertext = "";
            for (int i = 0; i < plainText.Length; i += 2)
            {
                char Letter1 = plainText[i];
                char Letter2;
                if (i + 1 < plainText.Length)
                {
                    Letter2 = plainText[i + 1];
                }
                else
                {
                    Letter2 = 'x';
                }
                if (Letter1 == Letter2)
                {
                    Letter2 = 'x';
                    i--;
                }

                int[] firstLetterindice = getINdices(matrix, Letter1);
                int[] secondLetterindice = getINdices(matrix, Letter2);

                char encrypted1;
                char encrypted2;

                if (firstLetterindice[0] == secondLetterindice[0])
                {
                    encrypted1 = matrix[firstLetterindice[0], (firstLetterindice[1] + 1) % 5];
                    encrypted2 = matrix[secondLetterindice[0], (secondLetterindice[1] + 1) % 5];
                }
                else if (firstLetterindice[1] == secondLetterindice[1])
                {
                    encrypted1 = matrix[(firstLetterindice[0] + 1) % 5, firstLetterindice[1]];
                    encrypted2 = matrix[(secondLetterindice[0] + 1) % 5, secondLetterindice[1]];
                }
                else
                {
                    encrypted1 = matrix[firstLetterindice[0], secondLetterindice[1]];
                    encrypted2 = matrix[secondLetterindice[0], firstLetterindice[1]];
                }

                ciphertext += encrypted1;
                ciphertext += encrypted2;
            }

            return ciphertext;

        }
        private char[,] getMatrix(string key)
        {
            char[,] matrix = new char[5, 5];
            string cleankey = denyRepeation(key + "abcdefghiklmnopqrstuvwxyz");
            int index = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {

                    matrix[i, j] = cleankey[index];
                    index++;

                }
            }

            return matrix;
        }

        private string denyRepeation(string combination)
        {
            string re = "";
            foreach (char y in combination)
            {
                if (!re.Contains(y))
                {
                    re += y;
                }
            }
            return re;
        }

        private int[] getINdices(char[,] matrix, char letter)
        {
            int[] indice = new int[2];

            for (int row = 0; row < 5; row++)
            {
                for (int col = 0; col < 5; col++)
                {
                    if (matrix[row, col] == letter)
                    {
                        indice[0] = row;
                        indice[1] = col;
                        return indice;
                    }
                }
            }

            return indice;
        }
    }
}