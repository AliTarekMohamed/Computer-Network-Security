using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        char[] chars = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' }; 
        public Dictionary<char, int> prepare_alphabets()
        {
            Dictionary<char, int> alphabets = new Dictionary<char, int>();

            for (int i = 0; i < 26; i++)
            {
                alphabets[chars[i]] = i;
            }

            return alphabets;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            plainText = plainText.ToLower();
            Dictionary<char, int> alphabets = prepare_alphabets();

            int key_length = key.Length;

            if (key.Length < plainText.Length)
            {
                for(int i = 0; i < (plainText.Length - key_length); i++)
                {
                    key += plainText[i % plainText.Length];
                }
            }

            for(int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] == ' ')
                {
                    continue;
                }
                cipherText += chars[(alphabets[plainText[i]] + alphabets[key[i]]) % 26];
            }

            return cipherText;
        }

        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            cipherText = cipherText.ToLower();
            Dictionary<char, int> alphabets = prepare_alphabets();

            int key_length = key.Length;

            if (key.Length < cipherText.Length)
            {
                for (int i = 0; i < (cipherText.Length - key_length); i++)
                {
                    int char_index = alphabets[cipherText[i]] - alphabets[key[i]];
                    if (char_index < 0)
                    {
                        char_index += 26;
                    }
                    if (cipherText[i] == ' ')
                    {
                        continue;
                    }
                    plainText += chars[char_index % 26];
                    key += plainText[i];
                }
            }

            for (int i = (cipherText.Length - key_length); i < cipherText.Length; i++)
            {
                int char_index = alphabets[cipherText[i]] - alphabets[key[i]];
                if (char_index < 0)
                {
                    char_index += 26;
                }
                if (cipherText[i] == ' ')
                {
                    continue;
                }

                plainText += chars[char_index % 26];
            }

            return plainText;
        }

        public string Analyse(string plainText, string cipherText)
        {
            int counter = 0;
            string key = "", tmp_key = "";
            Dictionary<char, int> alphabets = prepare_alphabets();

            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            // get all the key with its repeating plain text
            for (int i = 0; i < cipherText.Length; i++)
            {
                int c = alphabets[cipherText[i]] - alphabets[plainText[i]];
                c = (c < 0) ? (c + 26) : c;

                tmp_key += chars[c];

                if (tmp_key[i] == plainText[counter])
                {
                    counter++;  //counter = number of chars of plain text that included in key
                }
                else
                {
                    counter = 0;    //if the key and plain text has the same char & the key does not complete
                }
            }

            for (int i = 0; i < (plainText.Length - counter); i++)
            {
                key += tmp_key[i];
            }

            return key;
        }
    }
}
