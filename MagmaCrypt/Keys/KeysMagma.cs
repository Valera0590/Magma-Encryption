using System.Text;

namespace MagmaCrypt.Keys
{
    internal class KeysMagma
    {
        private const string _KeyString = "abcdefghijklmnopqrstuvwxyz123456";
        private static List<byte> _keyList = new(32);
        private static readonly List<uint> _keysRound = new(8);

        public static List<uint> KeysRound => _keysRound;

        public static void GenerateKeys()
        {
            _keyList = Encoding.GetEncoding(1251).GetBytes(_KeyString).ToList();
            for (int i = 0; i < 8; i++)
            {
                List<byte> kRBytes = _keyList.GetRange(i * 4, 4);
                kRBytes.Reverse();
                _keysRound.Add(BitConverter.ToUInt32(kRBytes.ToArray()));
            }
            /*Console.WriteLine("\nRound keys:\n");
            int ind = 1;
            foreach (var tmp in _keysRound)
            {
                Console.WriteLine(" K{0} = {1}  \t{2}", ind, tmp, ConvertBits.Convert64BitsToBinToString(tmp).Remove(0,42));
                ind++;
            }*/
        }
    }
}
