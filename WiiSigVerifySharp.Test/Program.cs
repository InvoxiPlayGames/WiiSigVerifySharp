using System.Text;

namespace WiiSigVerifySharp.Test
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // verifying RSA signatures as used in Tickets and TMDs
            // ca1.bin = CA00000001 certificate, from a TMD
            // cp4.bin = CP00000004 certificate, from a TMD

            WiiCertificate root = WiiIssuers.Root();

            Console.WriteLine("Root-CA00000001:");
            FileStream file_ca1 = File.OpenRead("ca1.bin");
            WiiCertificate ca1 = new(file_ca1);
            file_ca1.Close();
            Console.WriteLine($"  Issuer: {ca1.Issuer}");
            Console.WriteLine($"  Subject: {ca1.Subject}");
            Console.WriteLine($"  Key ID: {ca1.KeyID:X8}");
            Console.WriteLine($"  Valid: {root.VerifyChildCertificate(ca1)}");

            Console.WriteLine("Root-CA00000001-CP00000004:");
            FileStream file_cp4 = File.OpenRead("cp4.bin");
            WiiCertificate cp4 = new(file_cp4);
            file_cp4.Close();
            Console.WriteLine($"  Issuer: {cp4.Issuer}");
            Console.WriteLine($"  Subject: {cp4.Subject}");
            Console.WriteLine($"  Key ID: {cp4.KeyID:X8}");
            Console.WriteLine($"  Valid: {ca1.VerifyChildCertificate(cp4)}");

            // verifying ECDSA signatures as used in device certificates and signatures
            // consolecert.bin - output of ES_GetDeviceCert
            // titlecert.bin - certificate value from ES_Sign
            // titlesig.bin - signature value from ES_Sign

            WiiCertificate ms2 = WiiIssuers.MS00000002();

            Console.WriteLine("Device certificate:");
            FileStream fs = File.OpenRead("consolecert.bin");
            WiiCertificate device = new(fs);
            Console.WriteLine($"  Issuer: {device.Issuer}");
            Console.WriteLine($"  Subject: {device.Subject}");
            Console.WriteLine($"  Key ID: {device.KeyID:X8}");
            Console.WriteLine($"  Valid: {ms2.VerifyChildCertificate(device)}");

            Console.WriteLine("Title certificate:");
            FileStream fs2 = File.OpenRead("titlecert.bin");
            WiiCertificate title = new(fs2);
            Console.WriteLine($"  Issuer: {title.Issuer}");
            Console.WriteLine($"  Subject: {title.Subject}");
            Console.WriteLine($"  Key ID: {title.KeyID:X8}");
            Console.WriteLine($"  Valid: {device.VerifyChildCertificate(title)}");

            Console.WriteLine("Title signature:");
            byte[] signedDataBuffer = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
            byte[] titleSignatureData = File.ReadAllBytes("titlesig.bin");
            Console.WriteLine($"  Valid: {title.VerifySignature(signedDataBuffer, titleSignatureData)}");
        }
    }
}
