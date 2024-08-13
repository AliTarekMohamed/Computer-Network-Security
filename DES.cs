using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        private static int[] pc1 =
        {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        };
        private static int[] PC2_Table =
        {
            13, 16, 10, 23,  0,  4,
            2, 27, 14,  5, 20,  9,
            22, 18, 11,  3, 25,  7,
            15,  6, 26, 19, 12,  1,
            40, 51, 30, 36, 46, 54,
            29, 39, 50, 44, 32, 47,
            43, 48, 38, 55, 33, 52,
            45, 41, 49, 35, 28, 31
        };

        private static int[] init_permutation =
        {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };

        private static int[] P =
        {
            16,7,20,21,
            29,12,28,17,
            1,15,23,26,
            5,18,31,10,
            2,8,24,14,
            32,27,3,9,
            19,13,30,6,
            22,11,4,25
        };

        private static int[] inverse_permutaion =
        {
            40,8,48,16,56,24,64,32,
            39,7,47,15,55,23,63,31,
            38,6,46,14,54,22,62,30,
            37,5,45,13,53,21,61,29,
            36,4,44,12,52,20,60,28,
            35,3,43,11,51,19,59,27,
            34,2,42,10,50,18,58,26,
            33,1,41,9,49,17,57,25
        };

        private static int[] expantion_permutation =
        {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        };

        private static int[] numofshift = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        private static void convert_text_to_binary(int[] arr, string text)
        {
            int count = 0;
            string s2 = "";
            for (int i = 2; i < text.Length; i++)
            {
                s2 = Convert.ToString(Convert.ToInt32(text[i].ToString(), 16), 2).PadLeft(4, '0');
                for (int j = 0; j < s2.Length; j++)
                {
                    arr[count] = s2[j];
                    arr[count] -= 48;
                    count++;
                }
            }
        }
        private static void perm_Plain_text(int[] arr, int[,] mat)
        {
            int[,] ip = new int[,] {
                { 58, 50, 42, 34, 26, 18, 10, 2 },
                { 60, 52, 44, 36, 28, 20, 12, 4 },
                { 62, 54, 46, 38, 30, 22, 14, 6 },
                { 64, 56, 48, 40, 32, 24, 16, 8 },
                { 57, 49, 41, 33, 25, 17, 9, 1  },
                { 59, 51, 43, 35, 27, 19, 11, 3 },
                { 61, 53, 45, 37, 29, 21, 13, 5 },
                { 63, 55, 47, 39, 31, 23, 15, 7 }
            };

            int tmp;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    tmp = ip[i, j];
                    mat[i, j] = arr[tmp - 1];
                }
            }
        }
        private static void perm_Two_Key_Text(int[] arr, int[,] mat)
        {
            int[,] key_positions = new int[8, 6]
            {
                {14, 17, 11, 24, 1, 5},
                {3, 28, 15, 6, 21, 10},
                {23, 19, 12, 4, 26, 8},
                {16, 7, 27, 20, 13, 2},
                {41, 52, 31, 37, 47, 55},
                {30, 40, 51, 45, 33, 48},
                {44, 49, 39, 56, 34, 53},
                {46, 42, 50, 36, 29, 32}
            };

            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 6; j++)
                {
                    mat[i, j] = arr[key_positions[i, j] - 1];
                }
            }

        }
        private static void Shift_Left_one_bit(int[] a)
        {
            int _1st = a[0];

            for (int i = 0; i < a.Length - 1; i++)
            {
                a[i] = a[i + 1];
            }

            a[a.Length - 1] = _1st;
        }
        private static void Shift_Left_Two_bit(int[] arr)
        {
            Shift_Left_one_bit(arr);
            Shift_Left_one_bit(arr);
        }
        private static void Expand_Right(int[] Right, int[] NewRight)
        {
            int[] expansion = { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };

            for (int i = 0; i < expansion.Length; i++)
            {
                NewRight[i] = Right[expansion[i] - 1];
            }
        }
        private static void key_xor_rhalf(int[] key, int[] rhalf, int[] output)
        {
            for (int i = 0; i < 48; i++)
            {
                if (key[i] == rhalf[i])
                    output[i] = 0;
                else
                    output[i] = 1;

            }
        }

        private static void S1(int[] Right, int[] ArrS1)
        {
            int[] New_Right = new int[] {
                14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
            };
            int row_val = (ArrS1[0] << 1) | ArrS1[5];
            int col_val = (ArrS1[1] << 3) | (ArrS1[2] << 2) | (ArrS1[3] << 1) | ArrS1[4];
            int index = (row_val * 16) + col_val;
            int x = New_Right[index];
            string output = Convert.ToString(x, 2).PadLeft(4, '0');

            for (int i = 0; i < 4; i++)
            {
                Right[i] = output[i];
            }
        }
        private static void S2(int[] Right, int[] ArrS1)
        {
            int[] New_Right = new int[]
            {
                15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
            };
            int row_val = (ArrS1[0] << 1) | ArrS1[5];
            int col_val = (ArrS1[1] << 3) | (ArrS1[2] << 2) | (ArrS1[3] << 1) | ArrS1[4];
            int index = (row_val << 4) | col_val;
            int x = New_Right[index];
            string output = Convert.ToString(x, 2).PadLeft(4, '0');

            for (int i = 0; i < 4; i++)
            {
                Right[i] = output[i];
            }
        }
        private static void S3(int[] Right, int[] ArrS1)
        {
            int[] New_Right = new int[64]
            {
                10, 0 ,9 ,14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                13, 7 ,0 ,9 ,3 ,4 ,6 ,10 ,2, 8, 5, 14, 12, 11, 15, 1,
                13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5 ,10, 14, 7,
                1, 10, 13, 0, 6, 9, 8, 7 ,4 ,15, 14, 3, 11, 5, 2, 12
            };

            int row_val = (ArrS1[0] << 1) | ArrS1[5];
            int col_val = (ArrS1[1] << 3) | (ArrS1[2] << 2) | (ArrS1[3] << 1) | ArrS1[4];
            int index = (row_val * 16) + col_val;
            int x = New_Right[index];
            string output = Convert.ToString(x, 2).PadLeft(4, '0');

            for (int i = 0; i < 4; i++)
            {
                Right[i] = output[i];
            }

        }
        private static void S4(int[] Right, int[] ArrS1)
        {
            int[] New_Right = new int[64]
            {
                7, 13, 14, 3 ,0 ,6 ,9 ,10 ,1 ,2 ,8, 5, 11, 12, 4, 15,
                13, 8 ,11 ,5 ,6 ,15, 0 ,3 ,4 ,7 ,2 ,12, 1, 10, 14, 9,
                10 ,6 ,9 ,0 ,12 ,11, 7 ,13 ,15, 1, 3, 14, 5, 2, 8, 4,
                3, 15, 0 ,6 ,10, 1, 13, 8 ,9 ,4, 5, 11, 12, 7, 2, 14
            };

            int count = 0;
            int[,] mat = new int[4, 16];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    mat[i, j] = New_Right[count];
                    count++;
                }
            }

            string row = ArrS1[0].ToString() + ArrS1[5].ToString();
            string col = ArrS1[1].ToString() + ArrS1[2].ToString() + ArrS1[3].ToString() + ArrS1[4].ToString();

            int row_val = int.Parse(Convert.ToInt32(row, 2).ToString());
            int col_val = int.Parse(Convert.ToInt32(col, 2).ToString());

            int x = mat[row_val, col_val];
            string output = Convert.ToString(x, 2).PadLeft(4, '0');

            for (int i = 0; i < 4; i++)
            {
                Right[i] = output[i];
            }

        }
        private static void S5(int[] Right, int[] ArrS1)
        {
            int[] New_Right = new int[64] {
                2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
            };

            int row_val = (ArrS1[0] << 1) | ArrS1[5];
            int col_val = (ArrS1[1] << 3) | (ArrS1[2] << 2) | (ArrS1[3] << 1) | ArrS1[4];
            int index = (row_val * 16) + col_val;
            int x = New_Right[index];
            string output = Convert.ToString(x, 2).PadLeft(4, '0');

            for (int i = 0; i < 4; i++)
            {
                Right[i] = output[i];
            }
        }
        private static void S6(int[] Right, int[] ArrS1)
        {
            int[] New_Right = new int[64] {
                12 ,1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
            };

            int row_val = (ArrS1[0] << 1) | ArrS1[5];
            int col_val = (ArrS1[1] << 3) | (ArrS1[2] << 2) | (ArrS1[3] << 1) | ArrS1[4];
            int index = (row_val * 16) + col_val;
            int x = New_Right[index];
            string output = Convert.ToString(x, 2).PadLeft(4, '0');

            for (int i = 0; i < 4; i++)
            {
                Right[i] = output[i];
            }
        }
        private static void S7(int[] Right, int[] ArrS1)
        {
            int[] New_Right = new int[64]
            {
                4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
            };

            int row_val = (ArrS1[0] << 1) | ArrS1[5];
            int col_val = (ArrS1[1] << 3) | (ArrS1[2] << 2) | (ArrS1[3] << 1) | ArrS1[4];
            int index = (row_val * 16) + col_val;
            int x = New_Right[index];
            string output = Convert.ToString(x, 2).PadLeft(4, '0');

            for (int i = 0; i < 4; i++)
            {
                Right[i] = output[i];
            }
        }
        private static void S8(int[] Right, int[] ArrS1)
        {
            int[] New_Right = new int[64]
            {
                13 ,2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
            };

            int row_val = (ArrS1[0] << 1) | ArrS1[5];
            int col_val = (ArrS1[1] << 3) | (ArrS1[2] << 2) | (ArrS1[3] << 1) | ArrS1[4];
            int index = (row_val * 16) + col_val;
            int x = New_Right[index];
            string output = Convert.ToString(x, 2).PadLeft(4, '0');

            for (int i = 0; i < 4; i++)
            {
                Right[i] = output[i];
            }
        }
        private static void from_S1_TO_S8(int[] value, int[] key_xor_right_final)
        {
            int count_key_xor_right_final = 0;
            for (int collectKey = 0; collectKey < 8; collectKey++)
            {
                int[] arr = new int[6];
                for (int i = 0; i < 6; i++)
                {
                    arr[i] = value[collectKey * 6 + i];
                }
                int[] x = new int[4];
                switch (collectKey)
                {
                    case 0: S1(x, arr); break;
                    case 1: S2(x, arr); break;
                    case 2: S3(x, arr); break;
                    case 3: S4(x, arr); break;
                    case 4: S5(x, arr); break;
                    case 5: S6(x, arr); break;
                    case 6: S7(x, arr); break;
                    case 7: S8(x, arr); break;
                }
                for (int i = 0; i < 4; i++)
                {
                    key_xor_right_final[count_key_xor_right_final] = x[i] - 48;
                    count_key_xor_right_final++;
                }
            }
        }

        private static void permutation_3(int[] enter, int[] back)
        {
            int[] ip = new int[]
            {
                16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
                2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25
            };
            int tmp;
            for (int i = 0; i < 32; i++)
            {
                tmp = ip[i];
                back[i] = enter[tmp - 1];
            }
        }
        private static void left_xor_out_of_perm(int[] permval, int[] lhalf, int[] output)
        {
            for (int i = 0; i < 32; i++)
            {
                if (permval[i] == lhalf[i])
                    output[i] = 0;
                else
                    output[i] = 1;
            }
        }
        private static void last_permutation(int[] last_enter, int[] last_back)
        {
            int[] ip = new int[]
            {
                40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
                38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
                36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
                34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
            };
            int tmp;
            for (int i = 0; i < 64; i++)
            {
                tmp = ip[i];
                last_back[i] = last_enter[tmp - 1];
            }
        }
        private static void convert_from_binary_to_hexa(int[] arr, ref string hexa)
        {

            Dictionary<string, char> BinaryToHex = new Dictionary<string, char>()
            {
                { "0000", '0' },
                { "0001", '1' },
                { "0010", '2' },
                { "0011", '3' },
                { "0100", '4' },
                { "0101", '5' },
                { "0110", '6' },
                { "0111", '7' },
                { "1000", '8' },
                { "1001", '9' },
                { "1010", 'A' },
                { "1011", 'B' },
                { "1100", 'C' },
                { "1101", 'D' },
                { "1110", 'E' },
                { "1111", 'F' }
            };

            string hex = "";
            string bits = "";

            for (int i = 0; i < arr.Length; i++)
            {
                bits += arr[i];

                if (bits.Length == 4)
                {
                    char hexDigit = BinaryToHex[bits];
                    hex += hexDigit;
                    bits = "";
                }
            }
            hexa = "0x" + hex;
        }
        public override string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();

            int[] Bit_64_plain = new int[64];

            convert_text_to_binary(Bit_64_plain, plainText);
            int[,] mat_plain = new int[8, 8];
            perm_Plain_text(Bit_64_plain, mat_plain);
            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    sb.Append(mat_plain[i, j]);
                }
            }
            string IP = sb.ToString();

            int[] Bit_64_Key = new int[64];
            convert_text_to_binary(Bit_64_Key, key);
            int[] PC1_Table =
            {
                57, 49, 41, 33, 25, 17, 9,
                1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27,
                19, 11, 3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15,
                7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29,
                21, 13, 5, 28, 20, 12, 4
            };
            int[] permutedKey = new int[56];
            for (int i = 0; i < 56; i++)
            {
                permutedKey[i] = Bit_64_Key[PC1_Table[i] - 1];
            }

            int[] C = new int[28];
            int[] D = new int[28];
            for (int i = 0; i < 28; i++)
            {
                C[i] = permutedKey[i];
                D[i] = permutedKey[i + 28];
            }
            List<int[]> All_Keys = new List<int[]>();
            int Round_Key = 1;
            while (Round_Key != 17)
            {
                int[] keyCD = new int[48];
                int[] Last_key = new int[C.Length + D.Length];
                int[,] mat_Key_perm2 = new int[8, 6];

                if (Round_Key == 1 || Round_Key == 2 || Round_Key == 9 || Round_Key == 16)
                {
                    Shift_Left_one_bit(C);
                    Shift_Left_one_bit(D);

                    int cnt = 0;
                    for (int i = 0; i < Last_key.Length; i++)
                    {
                        if (i >= C.Length)
                        {
                            Last_key[i] = D[cnt];
                            cnt++;
                            continue;
                        }
                        Last_key[i] = C[i];
                    }
                    perm_Two_Key_Text(Last_key, mat_Key_perm2);
                    int c1 = 0;
                    for (int i = 0; i < 8; i++)
                    {
                        for (int j = 0; j < 6; j++)
                        {
                            keyCD[c1] = mat_Key_perm2[i, j];
                            c1++;
                        }
                    }
                    All_Keys.Add(keyCD);
                }
                else
                {
                    Shift_Left_Two_bit(C);
                    Shift_Left_Two_bit(D);
                    int cnt2 = 0;
                    for (int i = 0; i < Last_key.Length; i++)
                    {
                        if (i >= C.Length)
                        {
                            Last_key[i] = D[cnt2];
                            cnt2++;
                            continue;
                        }
                        Last_key[i] = C[i];
                    }

                    perm_Two_Key_Text(Last_key, mat_Key_perm2);
                    int c2 = 0;
                    for (int i = 0; i < 8; i++)
                    {
                        for (int j = 0; j < 6; j++)
                        {
                            keyCD[c2] = mat_Key_perm2[i, j];
                            c2++;
                        }
                    }
                    All_Keys.Add(keyCD);
                }
                Round_Key++;
            }
            // Divide IP into Left and Right
            int[] Left_IP = IP.Take(IP.Length / 2).Select(c => c - '0').ToArray();
            int[] Right_IP = IP.Skip(IP.Length / 2).Select(c => c - '0').ToArray();

            List<int[]> Left_List = new List<int[]> { Left_IP };
            List<int[]> Right_List = new List<int[]> { Right_IP };

            for (int i = 0; i < 16; i++)
            {
                Left_List.Add(Right_List[i]);

                int[] new_right_IP = new int[48];
                Expand_Right(Right_List[i], new_right_IP);

                int[] value = new int[48];
                key_xor_rhalf(All_Keys[i], new_right_IP, value);

                int[] key_for_round1 = new int[32];
                from_S1_TO_S8(value, key_for_round1);

                int[] permed_key3 = new int[32];
                permutation_3(key_for_round1, permed_key3);

                int[] last_Right = new int[32];
                left_xor_out_of_perm(permed_key3, Left_List[i], last_Right);

                Right_List.Add(last_Right);
            }
            int[] L16 = new int[32];
            int[] R16 = new int[32];
            R16 = Right_List.LastOrDefault();
            L16 = Left_List.LastOrDefault();

            int[] full_key = new int[L16.Length + R16.Length];

            for (int i = 0; i < full_key.Length / 2; i++)
            {
                full_key[i] = R16[i];
            }
            int countee = 0;
            for (int i = full_key.Length / 2; i < full_key.Length; i++)
            {
                full_key[i] = L16[countee];
                countee++;
            }

            int[] last_arr = new int[64];
            last_permutation(full_key, last_arr);

            string x = "";
            convert_from_binary_to_hexa(last_arr, ref x);
            return x;
        }


        private static int[,] createallofkeys(string key)
        {
            string keybin = Convert.ToString(Convert.ToInt64(key, 16), 2);
            while (keybin.Length < 64)
                keybin = '0' + keybin;

            string keyafterpc1 = "";
            for (int i = 0; i < pc1.Length; i++)
            {
                keyafterpc1 = keyafterpc1 + keybin[pc1[i] - 1];
            }
            int[] arrkeyleft = new int[28];
            int[] arrkeyright = new int[28];
            string keyleft = keyafterpc1.Substring(0, keyafterpc1.Length / 2);
            string keyright = keyafterpc1.Substring(keyafterpc1.Length / 2);
            for (int i = 0; i < keyleft.Length; i++)
            {
                arrkeyleft[i] = Convert.ToInt32(keyleft[i]) - 48;
                arrkeyright[i] = Convert.ToInt32(keyright[i]) - 48;
            }

            int[,] allofkeys = new int[16, 48];
            for (int i = 0; i < 16; i++)
            {
                for (int j = 1; j <= numofshift[i]; j++)
                {
                    int templeft = arrkeyleft[0];
                    int tempright = arrkeyright[0];
                    for (int k = 1; k < arrkeyleft.Length; k++)
                    {
                        arrkeyleft[k - 1] = arrkeyleft[k];
                        arrkeyright[k - 1] = arrkeyright[k];
                    }
                    arrkeyleft[arrkeyleft.Length - 1] = templeft;
                    arrkeyright[arrkeyright.Length - 1] = tempright;
                }

                for (int j = 0; j < allofkeys.GetLength(1); j++)
                {
                    if (PC2_Table[j] < 28)
                    {
                        allofkeys[i, j] = arrkeyleft[PC2_Table[j]];
                    }
                    else if (PC2_Table[j] < 56)
                    {
                        allofkeys[i, j] = arrkeyright[PC2_Table[j] - 28];
                    }
                }

            }
            return allofkeys;
        }
        public override string Decrypt(string cipherText, string key)
        {
            string plainText = "", tmp_plain = "", cipherTextP = "";
            string[] right_halves = new string[17];
            string[] left_halves = new string[17];
            int[] s_box_result = new int[32];
            int[] s_box_result_P = new int[32];

            cipherText = cipherText.Substring(2);
            cipherText = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');

            //[1] Initial Permutation
            for (int i = 0; i < init_permutation.Length; i++)
            {
                cipherTextP += cipherText[init_permutation[i] - 1];
            }

            //[2] Split Permutated Cipher into L & R
            left_halves[16] = cipherTextP.Substring(0, cipherTextP.Length / 2);
            right_halves[16] = cipherTextP.Substring(cipherTextP.Length / 2);

            //[3] Generate 16 Subkeys
            key = key.Substring(2);
            int[,] allofkeys = createallofkeys(key);

            for (int i = 16; i > 0; i--)
            {
                //[4.1] Right Half Expantion from 32 bits to 48 bits
                string rExp = "";
                for (int j = 0; j < expantion_permutation.Length; j++)
                {
                    rExp += right_halves[i][expantion_permutation[j] - 1];
                }

                //[4.2] XORing
                int[] xor = new int[48];
                for (int j = 0; j < rExp.Length; j++)
                {
                    xor[j] = Convert.ToInt32(Convert.ToString(Convert.ToInt32(rExp[j]) ^ Convert.ToInt32(allofkeys[i - 1, j]), 2).Substring(5));
                }

                //[4.3] S_Box
                Array.Clear(s_box_result, 0, s_box_result.Length);
                from_S1_TO_S8(xor, s_box_result);

                //[4.4] Permutation
                Array.Clear(s_box_result_P, 0, s_box_result_P.Length);
                for (int j = 0; j < P.Length; j++)
                {
                    s_box_result_P[j] = s_box_result[P[j] - 1];
                }

                //[4.5] XORing
                for (int j = 0; j < 32; j++)
                {
                    right_halves[i - 1] += Convert.ToString(Convert.ToInt32(s_box_result_P[j]) ^ Convert.ToInt32(left_halves[i][j]), 2).Substring(5);
                }
                left_halves[i - 1] = right_halves[i];
            }

            //[5] Concatenation
            tmp_plain += (right_halves[0] + right_halves[1]);

            //[6] Inverse Permutation
            for (int j = 0; j < inverse_permutaion.Length; j++)
            {
                plainText += tmp_plain[inverse_permutaion[j] - 1];
            }

            long x = Convert.ToInt64(plainText, 2);
            plainText = "0x" + x.ToString("X").PadLeft(16, '0');

            return plainText;
        }
    }
}