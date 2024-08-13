using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        string temp = "ETAOINSRHLDCUMFPGWYBVKXJQZ";
        public string Analyse(string plainText, string cipherText)
        {
            //abc  //fgy
            string res = "";
            int x = 0;
            SortedDictionary<char, char> d = new SortedDictionary<char, char>();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            temp = temp.ToLower();
            for (int i = 0; i < plainText.Length; i++)
            {
                if (!d.ContainsKey(plainText[i]))
                    d.Add(plainText[i], cipherText[i]);
            }
            for (char i = 'a'; i <= 'z'; i++)
            {
                if (d.ContainsKey(i))
                {
                    res += d[i];
                }
                else
                {
                    for (int j = 0; j < 26; j++)
                    {
                        if (!d.ContainsValue(temp[j]))
                        {
                            res += temp[j];
                            d.Add(i, temp[j]);
                            break;
                        }
                    }
                }
            }
            return res;
            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            string plainText = null;
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                int j = 0;
                while(true)
                {
                    if (cipherText[i] == key[j])
                    {
                        plainText += Convert.ToChar(97 + j);
                        break;
                    }
                    j++;
                }
            }
            return plainText;

        }

        public string Encrypt(string plainText, string key)
        {
           string cipherText=null ;
            plainText = plainText.ToLower();
            for (int i = 0; i < plainText.Length; i++)
            {
                cipherText += key[plainText[i] - 'a'];
            }
            return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	=
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        /// 

        public string AnalyseUsingCharFrequency(string cipher)
        {
            string plain="";
            temp = temp.ToLower();
            cipher = cipher.ToLower();
            SortedSet<int> pp = new SortedSet<int>();
            Dictionary<char, int> p = new Dictionary<char, int>();
            Dictionary<char, char> n = new Dictionary<char, char>();
            for (int i = 0; i < cipher.Length; i++) {
                if (!p.ContainsKey(cipher[i]))
                    p.Add(cipher[i],1);
                else
                    p[cipher[i]]++;
            }
            var sortedDictByOrder = p.OrderByDescending(v => v.Value);
            int c = 0;
            foreach(var i in sortedDictByOrder)
            {
                n.Add(i.Key, temp[c++]);
            }
            for (int i = 0; i < cipher.Length; i++)
            {
                plain += n[cipher[i]];
            }
            return plain;
            //throw new NotImplementedException();
        }
    }
}