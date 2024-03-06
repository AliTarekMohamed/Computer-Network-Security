using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
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

            if (key_length < plainText.Length)
            {
                for (int i = 0; i < (plainText.Length - key_length); i++)
                {
                    key += key[i % key_length];
                }
            }

            for (int i = 0; i < plainText.Length; i++)
            {
                if(plainText[i] == ' ')
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

            if (key_length < cipherText.Length)
            {
                for (int i = 0; i < (cipherText.Length - key_length); i++)
                {
                    key += key[i % key_length];
                }
            }

            for (int i = 0; i < cipherText.Length; i++)
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
            int counter = 0, length = -1;
            string tmp = "", key = "";
            Dictionary<char, int> alphabets = prepare_alphabets();

            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            for (int i = 0; i < plainText.Length; i++)
            {
                int char_index = alphabets[cipherText[i]] - alphabets[plainText[i]];
                if (char_index < 0)
                {
                    char_index += 26;
                }

                tmp += chars[char_index % 26];

                if (key == "")
                {
                    key += tmp[i];
                    continue;
                }

                if (tmp[i] != key[counter])
                {
                    if (counter != 0)
                    {
                        for(int j = counter; j > 0; j--)
                        {
                            key += tmp[i - j];
                            counter = 0;
                        }
                    }
                    key += tmp[i];
                }
                else
                {
                    length = key.Length;
                    counter++;
                }

                if (counter == length)
                {
                    break;
                }
            }
            return key;
        }
    }
}