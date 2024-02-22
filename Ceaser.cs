using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {

        public string Encrypt(string plainText, int key)
        {
            int ascii;
            string cipher_text = "";

            if (key > 26)
            {
                key %= 26;
            }

            foreach (char letter in plainText)
            {
                ascii = (int)letter;
                if (ascii >= 65 && ascii <= 90)
                {
                    ascii += key;
                    if (ascii > 90)
                    {
                        ascii = (ascii % 90) + 64;
                    }
                }
                else if (ascii >= 97 && ascii <= 122)
                {
                    ascii += key;
                    if (ascii > 122)
                    {
                        ascii = (ascii % 122) + 96;
                    }
                }
                cipher_text += (char)ascii;
            }
            return cipher_text;
        }

        public string Decrypt(string cipherText, int key)
        {
            int ascii;
            string plain_text = "";

            if (key > 26)
            {
                key %= 26;
            }

            foreach (char letter in cipherText)
            {
                ascii = (int)letter;
                if (ascii >= 65 && ascii <= 90)
                {
                    ascii -= key;
                    if (ascii < 65)
                    {
                        ascii = (90 - (64 - ascii));
                    }
                }
                else if (ascii >= 97 && ascii <= 122)
                {
                    ascii -= key;
                    if (ascii < 97)
                    {
                        ascii = (122 - (96 - ascii));
                    }
                }
                plain_text += (char)ascii;
            }
            return plain_text;
        }

        public int Analyse(string plainText, string cipherText)
        {
            int key;

            key = (int)plainText[0] - (int)cipherText[0];

            if (key < 0)
            {
                key += 26;
            }

            return key;
        }
    }
}