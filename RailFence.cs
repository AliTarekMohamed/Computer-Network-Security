using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)

        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            cipherText = cipherText.Replace("x", "");

            int key = 2;

            while (true)
            {
                string encrypted = Encrypt(plainText, key);
                if (string.Equals(encrypted, cipherText)) break;
                else
                    key++;
            }

            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            int col = Convert.ToInt32(Math.Ceiling((double)cipherText.Length / (double)key));

            char[,] matrix = new char[key, col];

            int counter = 0;

            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < col; j++)
                {

                    if (counter < cipherText.Length)
                    {

                        matrix[i, j] = cipherText[counter++];
                    }

                    else break;

                }
            }

            string decryption = null;

            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (matrix[j, i] != '\0')
                        decryption += matrix[j, i];
                }
            }

            return decryption;
        }

        public string Encrypt(string plainText, int key)
        {
            plainText = plainText.Trim();
            int col = Convert.ToInt32(Math.Ceiling((double)plainText.Length / (double)key));

            Console.WriteLine(col);

            char[,] matrix = new char[key, col];
            Console.WriteLine(matrix.Length);
            int counter = 0;


            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < key; j++)
                {

                    if (counter < plainText.Length)
                    {

                        matrix[j, i] = plainText[counter++];
                    }


                }
            }
            string encryption = null;

            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (matrix[i, j] != '\0')
                        encryption += matrix[i, j];
                }
            }

            return encryption.Trim();
        }
    }
}
