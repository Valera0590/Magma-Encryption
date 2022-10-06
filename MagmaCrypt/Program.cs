using System.Text;
using Algorithms;
using Keys;

Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
ProgramOne.Main();
static class ProgramOne
{
    public static void Main()
    {
        Console.Write("Input string to encrypt: ");
        string strInput = Console.ReadLine();
        
        KeysMagma.GenerateKeys();
        string strOutputEncryptMagma = EncryptionMagma.Magma(strInput, true);
        Console.WriteLine("\nString after encryption: {0}", strOutputEncryptMagma);
        Console.WriteLine("\n\n\t--------------------------\tDecrypting\t--------------------------\n");
        string strOutputDecryptMagma = EncryptionMagma.Magma(strOutputEncryptMagma, false);
        Console.WriteLine("\nString after decryption: {0}", strOutputDecryptMagma);

    }
}

