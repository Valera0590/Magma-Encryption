using System.Text;
using MagmaCrypt.Encryptions;

Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
ProgramOne.Main();
static class ProgramOne
{
    public static void Main()
    {
        Console.Write("Input string to encrypt: ");
        string strInput = Console.ReadLine();

        //EncryptionModes.ECB(strInput);
        EncryptionModes.CBC(strInput);

    }
}

