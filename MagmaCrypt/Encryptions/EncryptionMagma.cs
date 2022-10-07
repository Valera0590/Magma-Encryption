using System.Text;
using MagmaCrypt.Operations;
using MagmaCrypt.Data;
using MagmaCrypt.Keys;

namespace MagmaCrypt.Encryptions
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
            //Console.WriteLine("Key round is: \t\t\t{0}", OperationsBits.Convert64BitsToBinToString(keyRound));

            return (((ulong)(right) << 32) | (ulong)left ^ EncryptRight(right ^ keyRound));
        }
        private static ulong LastRound(ulong sixtyFourBits)
        {
            return ((sixtyFourBits % ((ulong)UInt32.MaxValue + 1)) << 32) | (sixtyFourBits >> 32);
        }
        public static string Magma(string input, bool flagEncrypt)
        {
            List<byte> strBytesList = Encoding.GetEncoding(1251).GetBytes(input).ToList();
            //заполнение недостающих байт в 8 байтовом блоке
            if (strBytesList.Count % 8 != 0)
            {
                _PlugCount = 8 - (strBytesList.Count % 8);
                List<byte> plugBytesList = Enumerable.Repeat(_FillerByte, _PlugCount).ToList();
                strBytesList.AddRange(plugBytesList);
            }
            strBytesList.Reverse();
            ulong res = BitConverter.ToUInt64(strBytesList.ToArray());

            //алгоритм шифрования или расшифрования в зависимости от флага
            if (flagEncrypt)
            {
                for (int i = 0; i < _Rounds; i++)
                {
                    //Console.WriteLine("\nStart block(BIN): \t\t{0}", OperationsBits.Convert64BitsToBinToString(res));
                    res = i < _RoundReverse ? Encrypt(res, KeysMagma.KeysRound[i % 8]) : Encrypt(res, KeysMagma.KeysRound[7 - (i % 8)]);
                    if (i == _Rounds - 1) res = LastRound(res);
                    //Console.WriteLine("Block after {0} round (BIN): \t{1}", i+1, OperationsBits.Convert64BitsToBinToString(res));
                }
                //Console.WriteLine("\nBlock after encryption(BIN): {0}", ConvertBits.Convert64BitsToBinToString(res));
                //Console.WriteLine("\nBlock after encryption: {0}", ConvertBits.Convert64BitsToStringBlock(res));
            }
            else
            {
                for (int i = _Rounds - 1; i >= 0; i--)
                {
                    //Console.WriteLine("\nStart block(BIN): \t\t{0}", OperationsBits.Convert64BitsToBinToString(res));
                    res = i < _RoundReverse ? Encrypt(res, KeysMagma.KeysRound[i % 8]) : Encrypt(res, KeysMagma.KeysRound[7 - (i % 8)]);
                    if (i == 0) res = LastRound(res);
                    //Console.WriteLine("Block after {0} round (BIN): \t{1}", i+1, OperationsBits.Convert64BitsToBinToString(res));
                }

                //Console.WriteLine("\nBlock after decryption(BIN): {0}", ConvertBits.Convert64BitsToBinToString(res));
                //Console.WriteLine("\nBlock after decryption: {0}", ConvertBits.Convert64BitsToStringBlock(res));
            }
            string strOutput = OperationsBits.Convert64BitsToStringBlock(res);

            if (flagEncrypt) return strOutput;
            if (_PlugCount > 0)
                strOutput = strOutput.Remove(strOutput.Length - (_PlugCount + 1), _PlugCount);
            _PlugCount = 0;
            return strOutput;
        }
    }

    internal class EncryptionModes
    {
        private const string VECTORINIT = "r2A!w@cT";

        public static void ECB(string input)
        {
            KeysMagma.GenerateKeys();
            List<byte> strBytesList = Encoding.GetEncoding(1251).GetBytes(input).ToList();
            List<byte> blockBytesList = new List<byte>(8);
            int blockCount = 0;
            string strOutput = "";

            while (blockCount < strBytesList.Count)
            {
                blockBytesList = strBytesList.Count - blockCount < 8 ?
                    strBytesList.GetRange(blockCount, strBytesList.Count - blockCount) : strBytesList.GetRange(blockCount, 8);

                strOutput += EncryptionMagma.Magma(Encoding.GetEncoding(1251).GetString(blockBytesList.ToArray()), true);
                Console.WriteLine("\nString after encrypting block {0} : {1}", blockCount / 8, strOutput);
                blockCount += 8;
            }

            string strOutputEncryptMagma = strOutput;
            Console.WriteLine("\n\nEncrypted message: {0}", strOutputEncryptMagma);

            Console.WriteLine("\n\n------------------------\tDecrypting\t------------------------\n");
            blockCount = 0;
            strOutput = "";
            strBytesList = Encoding.GetEncoding(1251).GetBytes(strOutputEncryptMagma).ToList();

            while (blockCount < strBytesList.Count)
            {
                blockBytesList = strBytesList.Count - blockCount < 8 ?
                    strBytesList.GetRange(blockCount, strBytesList.Count - blockCount) : strBytesList.GetRange(blockCount, 8);

                strOutput += EncryptionMagma.Magma(Encoding.GetEncoding(1251).GetString(blockBytesList.ToArray()), false);
                Console.WriteLine("\nString after decrypting block {0} : {1}", blockCount / 8, strOutput);
                blockCount += 8;
            }
            string strOutputDecryptMagma = strOutput;
            Console.WriteLine("\n\nSource decrypted message: {0}", strOutputDecryptMagma);
        }

        public static void CBC(string input)
        {
            KeysMagma.GenerateKeys();
            List<byte> strBytesList = Encoding.GetEncoding(1251).GetBytes(input).ToList();
            List<byte> currentBlockBytesList;
            int blockCount = 0;
            string strOutput = "";
            string strPreviousBlock = VECTORINIT;
            string strCurrentBlock;
            List<byte> previousBlockBytesList = Encoding.GetEncoding(1251).GetBytes(strPreviousBlock).ToList();

            while (blockCount < strBytesList.Count)
            {
                currentBlockBytesList = strBytesList.Count - blockCount < 8 ?
                    strBytesList.GetRange(blockCount, strBytesList.Count - blockCount) : strBytesList.GetRange(blockCount, 8);

                currentBlockBytesList = OperationsBits.XORListsBytes(previousBlockBytesList, currentBlockBytesList);

                strCurrentBlock = EncryptionMagma.Magma(Encoding.GetEncoding(1251).GetString(currentBlockBytesList.ToArray()), true);
                currentBlockBytesList = Encoding.GetEncoding(1251).GetBytes(strCurrentBlock).ToList();
                previousBlockBytesList = currentBlockBytesList;

                strOutput += strCurrentBlock;
                Console.WriteLine("\nString after encrypting block {0} : {1}", blockCount / 8, strOutput);
                blockCount += 8;
            }

            string strOutputEncryptMagma = strOutput;
            Console.WriteLine("\n\nEncrypted message: {0}", strOutputEncryptMagma);

            Console.WriteLine("\n\n------------------------\tDecrypting\t------------------------\n");
            strOutput = "";
            strBytesList = Encoding.GetEncoding(1251).GetBytes(strOutputEncryptMagma).ToList();
            blockCount = strBytesList.Count;
            currentBlockBytesList = previousBlockBytesList;

            while (blockCount >= 8)
            {
                if (blockCount % 8 != 0) blockCount += 8 - blockCount % 8;
                strCurrentBlock = EncryptionMagma.Magma(Encoding.GetEncoding(1251).GetString(currentBlockBytesList.ToArray()), false);
                
                previousBlockBytesList = blockCount > 8 ?
                    strBytesList.GetRange(blockCount - 16, 8) : Encoding.GetEncoding(1251).GetBytes(VECTORINIT).ToList();

                currentBlockBytesList = Encoding.GetEncoding(1251).GetBytes(strCurrentBlock).ToList();
                currentBlockBytesList = OperationsBits.XORListsBytes(previousBlockBytesList, currentBlockBytesList);
                strCurrentBlock = Encoding.GetEncoding(1251).GetString(currentBlockBytesList.ToArray());
                strOutput = new string(strCurrentBlock + strOutput);
                
                currentBlockBytesList = previousBlockBytesList;
                Console.WriteLine("\nString after decrypting block {0} : {1}", blockCount / 8, strOutput);
                blockCount -= 8;
            }

            string strOutputDecryptMagma = strOutput;
            Console.WriteLine("\n\nSource decrypted message: {0}", strOutputDecryptMagma);
        }
    }
}
