using System.Text;
using Keys;
using Converters;

namespace Algorithms
{
    internal class EncryptionMagma
    {
        private const short _Rounds = 32;
        private const short _RoundReverse = 24;
        private static int _PlugCount;
        private const byte _FillerByte = 176;
        private static readonly uint[,] _Pi = TablePermutationPI.PI;
        private static uint EncryptRight(uint right)
        {
            //Console.WriteLine("\nBlock before encrypt right(already xor k_r): \t{0}", ConvertBits.Convert64BitsToBinToString(right));
            byte[] rightBytes = BitConverter.GetBytes(right);
            List<byte> rightBytesList = rightBytes.ToList();
            rightBytesList.Reverse();
            List<byte> rightBytesListResult = new List<byte>(rightBytesList.Count);
            int i = 0;
            foreach (var rightByte in rightBytesList)
            {
                byte firstPartRightByte = (byte)_Pi[i, rightByte / 16];
                byte secondPartRightByte = (byte)_Pi[i + 1, rightByte % 16];
                rightBytesListResult.Add((byte)((firstPartRightByte << 4) | secondPartRightByte));
                i += 2;
            }

            rightBytesListResult.Reverse();
            right = BitConverter.ToUInt32(rightBytesListResult.ToArray());
            //Console.WriteLine("\nBlock after PI table permutation right: \t{0}", ConvertBits.Convert64BitsToBinToString(right));
            //Console.WriteLine("\nBlock after << 11 right part: \t\t\t{0}", ConvertBits.Convert64BitsToBinToString((right % 2097152 << 11 | right >> 21)));
            return (right % 2097152 << 11 | right >> 21);
        }

        private static ulong Encrypt(ulong sixtyFourBits, uint keyRound)
        {
            byte[] sixtyFourBitsToBytes = BitConverter.GetBytes(sixtyFourBits);
            List<byte> sixtyFourBytesList = sixtyFourBitsToBytes.ToList();
            sixtyFourBytesList.Reverse();
            List<byte> leftListBytes = sixtyFourBytesList.GetRange(0, 4);
            List<byte> rightListBytes = sixtyFourBytesList.GetRange(4, 4);
            leftListBytes.Reverse();
            rightListBytes.Reverse();

            uint left = BitConverter.ToUInt32(leftListBytes.ToArray());
            uint right = BitConverter.ToUInt32(rightListBytes.ToArray());
            //Console.WriteLine("\nBlock after dividing to left and right parts: \t{0}", ConvertBits.Convert64BitsToBinToString(((ulong)(left) << 32) | right));
            Console.WriteLine("\nKey round is: \t\t\t{0}", ConvertBits.Convert64BitsToBinToString(keyRound));

            return (((ulong)(right) << 32) | (ulong)left ^ EncryptRight(right ^ keyRound));
        }
        private static ulong LastRound(ulong sixtyFourBits)
        {
            return ((sixtyFourBits % ((ulong)UInt32.MaxValue + 1)) << 32) | (sixtyFourBits >> 32);
        }

        public static string Magma(string input, bool flagEncrypt)
        {
            List<byte> strBytesList = Encoding.GetEncoding(1251).GetBytes(input).ToList();
            List<byte> blockBytesList = new List<byte>(8);
            int blockCount = 0;
            string strOutput = "";
            ulong res;
            //заполнение недостающих байт в 8 байтовом блоке
            if (strBytesList.Count % 8 != 0)
            {
                _PlugCount = 8 - (strBytesList.Count % 8);
                List<byte> plugBytesList = Enumerable.Repeat(_FillerByte, _PlugCount).ToList();
                strBytesList.AddRange(plugBytesList);
            }
            while (blockCount < strBytesList.Count)
            {
                blockBytesList = strBytesList.GetRange(blockCount, 8);
                blockBytesList.Reverse();
                res = BitConverter.ToUInt64(blockBytesList.ToArray());

                //алгоритм шифрования или расшифрования в зависимости от флага
                if (flagEncrypt)
                {
                    for (int i = 0; i < _Rounds; i++)
                    {
                        Console.WriteLine("\nStart block(BIN): \t\t{0}", ConvertBits.Convert64BitsToBinToString(res));
                        res = i < _RoundReverse ? Encrypt(res, KeysMagma.KeysRound[i % 8]) : Encrypt(res, KeysMagma.KeysRound[7 - (i % 8)]);
                        if (i == _Rounds - 1) res = LastRound(res);
                        Console.WriteLine("\nBlock after {0} round (BIN): \t{1}\n", i+1, ConvertBits.Convert64BitsToBinToString(res));
                    }
                    //Console.WriteLine("\nBlock after encryption(BIN): {0}", ConvertBits.Convert64BitsToBinToString(res));
                    //Console.WriteLine("\nBlock after encryption: {0}", ConvertBits.Convert64BitsToStringBlock(res));
                }
                else
                {
                    for (int i = _Rounds - 1; i >= 0; i--)
                    {
                        Console.WriteLine("\nStart block(BIN): \t\t{0}", ConvertBits.Convert64BitsToBinToString(res));
                        res = i < _RoundReverse ? Encrypt(res, KeysMagma.KeysRound[i % 8]) : Encrypt(res, KeysMagma.KeysRound[7 - (i % 8)]);
                        if (i == 0) res = LastRound(res);
                        Console.WriteLine("\nBlock after {0} round (BIN): \t{1}\n", i+1, ConvertBits.Convert64BitsToBinToString(res));
                    }

                    //Console.WriteLine("\nBlock after decryption(BIN): {0}", ConvertBits.Convert64BitsToBinToString(res));
                    //Console.WriteLine("\nBlock after decryption: {0}", ConvertBits.Convert64BitsToStringBlock(res));
                }

                strOutput += ConvertBits.Convert64BitsToStringBlock(res);
                blockCount += 8;
            }

            if (flagEncrypt) return strOutput;
            if (_PlugCount > 0)
                strOutput = strOutput.Remove(strOutput.Length - _PlugCount, _PlugCount);
            _PlugCount = 0;
            return strOutput;
        }
    }
}
