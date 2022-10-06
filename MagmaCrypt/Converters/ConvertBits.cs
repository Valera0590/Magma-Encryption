using System.Text;

namespace Converters
{
    internal class ConvertBits
    {
        public static string Convert64BitsToBinToString(ulong sixtyFourBits)
        {
            string l = Convert.ToString((uint)(sixtyFourBits / ((ulong)UInt32.MaxValue + 1)), 2);
            string r = Convert.ToString((uint)(sixtyFourBits % ((ulong)UInt32.MaxValue + 1)), 2);
            string frm = "";
            while (frm.Length + l.Length < 32)
                frm += '0';
            l = l.Insert(0, frm);
            frm = "";
            while (frm.Length + r.Length < 32)
                frm += '0';
            r = r.Insert(0, frm);
            string formattedRes = l + r;
            int i = 0;
            while (i < formattedRes.Length)
            {
                formattedRes = formattedRes.Insert(i, " ");
                i += 5;
            }

            formattedRes = formattedRes.Insert(formattedRes.Length / 2, " ");
            return formattedRes;
        }

        public static string Convert64BitsToStringBlock(ulong sixtyFourBits)
        {
            byte[] sixtyFourBitsToBytes = BitConverter.GetBytes(sixtyFourBits);
            List<byte> sixtyFourBytesList = sixtyFourBitsToBytes.ToList();
            sixtyFourBytesList.Reverse();
            return Encoding.GetEncoding(1251).GetString(sixtyFourBytesList.ToArray());
        }
    }
}
