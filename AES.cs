using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        private int rconIndex = 0;
        private static int rconIndexP = 0;

        private static string[,] SBox = new string[16, 16]
        {
            {"63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76"},
            {"ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0"},
            {"b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15"},
            {"04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75"},
            {"09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84"},
            {"53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf"},
            {"d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8"},
            {"51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2"},
            {"cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73"},
            {"60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db"},
            {"e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79"},
            {"e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08"},
            {"ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a"},
            {"70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e"},
            {"e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df"},
            {"8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16"}
        };
        private static string[,] inverseSBox = new string[16, 16]
        {
            {"52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb"},
            {"7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb"},
            {"54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e"},
            {"08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25"},
            {"72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92"},
            {"6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84"},
            {"90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06"},
            {"d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b"},
            {"3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73"},
            {"96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e"},
            {"47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b"},
            {"fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4"},
            {"1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f"},
            {"60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef"},
            {"a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61"},
            {"17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d"}
        };
        private static string[,] Rcon = new string[4, 10]
        {
            {"01", "02", "04", "08", "10", "20", "40", "80", "1b", "36"},
            {"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},
            {"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},
            {"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"}
        };

        private static string[,] StringToMatrix(string str)
        {
            int iterator = 0;

            if (str[0] == '0' && str[1] == 'x')
            {
                str = str.Substring(2);
            }

            int len = (int)Math.Sqrt((double)(str.Length / 2)); //each element contain 2 digits and the matrix is square
            string[,] newStr = new string[len, len];

            for (int i = 0; i < len; i++)
            {
                for (int j = 0; j < len; j++)
                {
                    newStr[j, i] += str[iterator++];
                    newStr[j, i] += str[iterator++];
                }
            }
            return newStr;
        }
        private string[,] SubBytes(string[,] state)
        {
            int row, col, rows = state.GetLength(0), cols = state.GetLength(1);

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    /* May the number = (e.g) 0x05, so this number considered 1 digit (5)
                       and throw exception when accessing state[i, j][1]*/
                    try
                    {
                        row = Convert.ToInt32(state[i, j][0].ToString(), 16);
                        col = Convert.ToInt32(state[i, j][1].ToString(), 16);
                    }
                    catch
                    {
                        row = 0;
                        col = Convert.ToInt32(((state[i, j][0]).ToString()), 16);
                    }
                    state[i, j] = SBox[row, col];
                }
            }
            return state;
        }
        private static string[,] ShiftRows(string[,] state)
        {
            int rows = state.GetLength(0);
            int cols = state.GetLength(1);
            string temp1, temp2;

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < i; j++)     //number of shift repeating
                {
                    temp1 = state[i, 0];
                    for (int k = 0; k < cols - 1; k++)
                    {
                        temp2 = state[i, k];
                        state[i, k] = state[i, k + 1];
                        state[i, k + 1] = temp2;
                    }
                    state[i, cols - 1] = temp1;
                }
            }
            return state;
        }
        private static int Multiply(int mix, int state)
        {
            int result;
            if (mix == 1)
            {
                result = state;
            }
            else if (mix == 2)
            {
                if (state < 128)
                {
                    /*Mod 256 because when multiplying with 2
                     the number become greater than 8 bits*/
                    result = ((state << 1) % 256);
                }
                else
                {
                    result = ((state << 1) % 256) ^ Convert.ToInt32("1b", 16);
                }
            }
            else
            {
                if (state < 128)
                {
                    result = state ^ ((state << 1) % 256);
                }
                else
                {
                    result = state ^ ((state << 1) % 256) ^ Convert.ToInt32("1b", 16);
                }
            }
            return result;
        }
        private static string[,] MixColumns(string[,] state)
        {
            int sum;
            string[,] result = new string[4, 4];

            int[,] mix = new int[4, 4] {
                {2, 3, 1, 1},
                {1, 2, 3, 1},
                {1, 1, 2, 3},
                {3, 1, 1, 2}
            };

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    sum = 0;
                    for (int k = 0; k < 4; k++)
                    {
                        sum ^= Multiply(mix[i, k], Convert.ToInt32(state[k, j], 16));
                    }
                    result[i, j] = sum.ToString("X");
                }
            }
            return result;
        }
        private string[,] AddRoundKey(string[,] state, string[,] key)
        {
            int rows = state.GetLength(0);
            int cols = state.GetLength(1);
            string[,] newKey = new string[rows, cols];

            //XORing
            int xor;
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    xor = Convert.ToInt32(state[i, j], 16) ^ Convert.ToInt32(key[i, j], 16);
                    state[i, j] = xor.ToString("X");
                }
            }

            //Prepare first col in new key
            string[,] firstKeyCol = new string[rows, 1];
            for (int i = 1; i <= rows; i++)
            {
                firstKeyCol[i - 1, 0] = key[i % rows, cols - 1];
            }
            SubBytes(firstKeyCol);

            //Prepare new key
            for (int j = 0; j < cols; j++)
            {
                for (int i = 0; i < rows; i++)
                {
                    if (j == 0)
                    {
                        newKey[i, j] = (Convert.ToInt32(firstKeyCol[i, j], 16) ^ Convert.ToInt32(Rcon[i, rconIndex % 10], 16) ^ Convert.ToInt32(key[i, j], 16)).ToString("X");
                    }
                    else
                    {
                        newKey[i, j] = (Convert.ToInt32(newKey[i, j - 1], 16) ^ Convert.ToInt32(key[i, j], 16)).ToString("X");
                    }
                }
                if (j == 0)
                {
                    rconIndex++;
                }
            }
            return newKey;
        }
        public override string Encrypt(string plainText, string key)
        {
            int rounds = 10;
            string cipherText = "0x";

            string[,] newKey = StringToMatrix(key);
            string[,] newPlainText = StringToMatrix(plainText);
            int rows = newPlainText.GetLength(0), cols = newPlainText.GetLength(1);

            newKey = AddRoundKey(newPlainText, newKey);

            for (int i = 0; i < rounds - 1; i++)
            {
                SubBytes(newPlainText);
                ShiftRows(newPlainText);
                newPlainText = MixColumns(newPlainText);
                newKey = AddRoundKey(newPlainText, newKey);
            }

            SubBytes(newPlainText);
            ShiftRows(newPlainText);
            AddRoundKey(newPlainText, newKey);

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    if (newPlainText[j, i].Length == 2)
                    {
                        cipherText += newPlainText[j, i];
                    }
                    else
                    {
                        cipherText += '0' + newPlainText[j, i];
                    }
                }
            }
            return cipherText;
        }
        public static string XOR(string hex1, string hex2)
        {

            string resXOR = "";

            for (int i = 0; i < hex1.Length; i++)
            {
                if (hex1[i] == hex2[i])
                {
                    resXOR += '0';
                }
                else
                {
                    resXOR += '1';
                }
            }
            //Console.WriteLine(resXOR);


            return resXOR;
        }
        private static string[,] createallkeysP(string[,] keyarr)
        {
            string[,] allskeys = new string[4, 44];
            for (int i = 0; i < 11; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        try
                        {
                            allskeys[j, k + (i * 4)] = keyarr[j, k];
                        }
                        catch
                        {
                            Console.WriteLine("aia");
                        }

                    }
                }

                keyarr = createkeyP(keyarr);

            }
            return allskeys;
        }
        private static string[,] createkeyP(string[,] key)
        {
            int rows = key.GetLength(0);
            int cols = key.GetLength(1);
            string[,] newKey = new string[rows, cols];


            //Prepare first col in new key
            string[,] firstKeyCol = new string[rows, 1];
            for (int i = 1; i <= rows; i++)
            {
                firstKeyCol[i - 1, 0] = key[i % rows, cols - 1];
            }
            SubBytesP(firstKeyCol);

            //Prepare new key
            for (int j = 0; j < cols; j++)
            {
                for (int i = 0; i < rows; i++)
                {
                    if (j == 0)
                    {
                        newKey[i, j] = (Convert.ToInt32(firstKeyCol[i, j], 16) ^ Convert.ToInt32(Rcon[i, rconIndexP % 10], 16) ^ Convert.ToInt32(key[i, j], 16)).ToString("X");
                    }
                    else
                    {
                        newKey[i, j] = (Convert.ToInt32(newKey[i, j - 1], 16) ^ Convert.ToInt32(key[i, j], 16)).ToString("X");
                    }
                }
                if (j == 0)
                {
                    rconIndexP++;
                }
            }

            return newKey;
        }
        private static string[,] calcroundkeyP(string[,] key, int round)
        {
            string[,] res = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    res[i, j] = key[i, j + ((round - 1) * 4)];
                }
            }
            return res;
        }
        public static string[,] SubBytesP(string[,] state)
        {
            int row, col, rows = state.GetLength(0), cols = state.GetLength(1);

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    /* May the number = (e.g) 0x05, so this number considered 1 digit (5)
                       and throw exception when accessing state[i, j][1]*/
                    try
                    {
                        row = Convert.ToInt32(state[i, j][0].ToString(), 16);
                        col = Convert.ToInt32(state[i, j][1].ToString(), 16);
                    }
                    catch
                    {
                        row = 0;
                        col = Convert.ToInt32(((state[i, j][0]).ToString()), 16);
                    }
                    state[i, j] = SBox[row, col];
                }
            }
            return state;
        }
        private static string[,] INVSubBytesP(string[,] state)
        {
            int row, col, rows = state.GetLength(0), cols = state.GetLength(1);

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    /* May the number = (e.g) 0x05, so this number considered 1 digit (5)
                       and throw exception when accessing state[i, j][1]*/
                    try
                    {
                        row = Convert.ToInt32(state[i, j][0].ToString(), 16);
                        col = Convert.ToInt32(state[i, j][1].ToString(), 16);
                    }
                    catch
                    {
                        row = 0;
                        col = Convert.ToInt32(((state[i, j][0]).ToString()), 16);
                    }
                    state[i, j] = inverseSBox[row, col];
                }
            }
            return state;
        }
        private static string[,] INVShiftRowsP(string[,] k)
        {
            if (k.GetLength(0) >= 0 && k.GetLength(0) >= 4 && k.GetLength(1) >= 0 && k.GetLength(1) >= 4)
            {
                int i = 1;

                string temp = k[i, 3];
                k[i, 3] = k[i, 2];
                k[i, 2] = k[i, 1];
                k[i, 1] = k[i, 0];
                k[i, 0] = temp;

                i = 2;

                temp = k[i, 3];
                string temp1 = k[i, 2];
                k[i, 3] = k[i, 1];
                k[i, 2] = k[i, 0];
                k[i, 1] = temp;
                k[i, 0] = temp1;



                i = 3;

                temp = k[i, 0];
                k[i, 0] = k[i, 1];
                k[i, 1] = k[i, 2];
                k[i, 2] = k[i, 3];
                k[i, 3] = temp;
            }

            return k;


        }
        private static void AddRoundKeyP(string[,] state, string[,] key)
        {
            int rows = state.GetLength(0);
            int cols = state.GetLength(1);
            string[,] newKey = new string[rows, cols];

            //XORing
            int xor;
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    xor = Convert.ToInt32(state[i, j], 16) ^ Convert.ToInt32(key[i, j], 16);
                    state[i, j] = xor.ToString("X");
                }
            }

        }
        public static string GF(string cipher, string matrix)
        {
            string reslut = "";
            int res = 0;
            string bincipher = Convert.ToString(Convert.ToInt32(cipher, 16), 2);
            string binmatrix = Convert.ToString(Convert.ToInt32(matrix, 16), 2);
            int[] bincipherarr = { 0, 0, 0, 0, 0, 0, 0, 0 };
            int[] binmatrixarr = { 0, 0, 0, 0, 0, 0, 0, 0 };
            for (int i = 7, j = bincipher.Length - 1; j >= 0; i--, j--)
            {
                bincipherarr[i] = bincipher[j] - '0';

            }
            for (int i = 7, j = binmatrix.Length - 1; j >= 0; i--, j--)
            {
                binmatrixarr[i] = binmatrix[j] - '0';

            }
            int[,] binGF = new int[8, 8];

            for (int i = 0; i < 8; i++)
            {
                binGF[0, i] = bincipherarr[i];
            }
            for (int i = 1; i < 8; i++)
            {
                if (binGF[i - 1, 0] == 0)
                {

                    for (int j = 1; j < 8; j++)
                    {
                        binGF[i, j - 1] = binGF[i - 1, j];
                    }
                    binGF[i, 7] = 0;

                }
                else if (binGF[i - 1, 0] == 1)
                {
                    char[] temp = new char[8];
                    for (int j = 1; j < 8; j++)
                    {

                        temp[j - 1] = Convert.ToChar(binGF[i - 1, j] + 48);
                    }
                    temp[7] = '0';

                    string temp6 = new string(temp);

                    temp6 = XOR(temp6, "00011011");

                    for (int k = 7, aba = temp6.Length - 1; k >= 0; k--, aba--)
                    {
                        if (aba < 0)
                            binGF[i, k] = 0;
                        else
                            binGF[i, k] = temp6[aba] - '0';

                    }
                }
            }

            for (int i = 7; i >= 0; i--)
            {

                if (binmatrixarr[i] == 1)
                {
                    char[] temp3 = new char[8];
                    string temp5 = "";
                    for (int j = 0; j < 8; j++)
                    {
                        temp5 += (binGF[7 - i, j]);
                    }
                    int dic3 = Convert.ToInt32(temp5, 16);

                    res = res ^ dic3;
                }
            }

            reslut = res.ToString("x");
            return reslut;
        }
        public static string[,] mixcol(string[,] matrix2)
        {
            string invmix = "0e090d0b0b0e090d0d0b0e09090d0b0e";
            string[,] matrix1 = StringToMatrix(invmix);

            string[,] result = new string[matrix1.GetLength(0), matrix2.GetLength(1)];
            for (int i = 0; i < result.GetLength(0); i++)
            {
                for (int j = 0; j < result.GetLength(1); j++)
                {
                    int temp = 0;

                    for (int k = 0; k < matrix1.GetLength(1); k++)
                    {
                        string temp1 = GF(matrix1[i, k], matrix2[k, j]);

                        while (temp1.Length < 8)
                        {
                            temp1 = '0' + temp1;
                        }
                        temp ^= Convert.ToInt32(temp1, 16);
                    }
                    result[i, j] = temp.ToString("x");
                    while (result[i, j].Length < 8)
                    {
                        result[i, j] = '0' + result[i, j];
                    }
                    int decimalValue = Convert.ToInt32(result[i, j], 2);
                    string hexadecimalValue = Convert.ToString(decimalValue, 16);
                    result[i, j] = hexadecimalValue;
                    while (result[i, j].Length < 2)
                    {
                        result[i, j] = '0' + result[i, j];
                    }
                }
            }
            return result;
        }
        public override string Decrypt(string cipherText, string key)
        {
            int round = 11;
            string[,] keyarr = StringToMatrix(key);
            string[,] ciphermatrix = StringToMatrix(cipherText);

            string[,] all = createallkeysP(keyarr);
            string[,] roundkey = calcroundkeyP(all, round);
            round--;
            AddRoundKeyP(ciphermatrix, roundkey);
            for (int rounds = 10; rounds > 0; rounds--)
            {
                ciphermatrix = INVShiftRowsP(ciphermatrix);
                ciphermatrix = INVSubBytesP(ciphermatrix);
                roundkey = calcroundkeyP(all, round);
                round--;
                AddRoundKeyP(ciphermatrix, roundkey);
                if (rounds != 1)
                    ciphermatrix = mixcol(ciphermatrix);
            }

            string cipherText1 = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (ciphermatrix[j, i].Length == 2)
                    {
                        cipherText1 += ciphermatrix[j, i];
                    }
                    else
                    {
                        cipherText1 += '0' + ciphermatrix[j, i];
                    }
                }
            }
            cipherText1 = cipherText1.Insert(0, "0x");
            rconIndexP = 0;
            return cipherText1;
        }
    }
}