using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WiiSigVerifySharp
{
    internal enum WiiSignatureType : int
    {
        RSA4096 = 0x00010000,
        RSA2048 = 0x00010001,
        ECCB233 = 0x00010002
    }

    internal enum WiiKeyType : int
    {
        RSA4096 = 0x00000000,
        RSA2048 = 0x00000001,
        ECCB233 = 0x00000002
    }

    public class WiiCertificate
    {
        internal WiiSignatureType issuerSignatureType;
        internal byte[]? issuerSignatureData;

        internal byte[]? issuerStringBytes;
        public string? Issuer { internal set; get; }

        internal byte[]? subjectStringBytes;
        public string? Subject { internal set; get; }

        public uint? KeyID { internal set; get; }

        internal WiiKeyType keyType;
        internal uint keyExponent;
        internal byte[]? keyData;

        internal byte[] GetSignableBuffer()
        {
            MemoryStream ms = new();
            ms.Write(issuerStringBytes);
            ms.WriteUInt32BE((uint)keyType);
            ms.Write(subjectStringBytes);
            ms.WriteUInt32BE((uint)KeyID!);
            ms.Write(keyData);
            // add padding
            if (keyType == WiiKeyType.ECCB233)
            {
                ms.Seek(0x3C, SeekOrigin.Current);
            }
            else
            {
                ms.WriteUInt32BE(keyExponent);
                ms.Seek(0x34, SeekOrigin.Current);
            }
            return ms.GetBuffer().Take((int)ms.Position).ToArray();
        }

        public bool VerifySignature(byte[] buffer, byte[] signature)
        {
            if (keyType == WiiKeyType.ECCB233)
            {
                return WiiUtilities.VerifyECDSASha1(keyData!, buffer, signature);
            } else
            {
                return WiiUtilities.VerifyRSASha1(keyExponent, keyData!, buffer, signature);
            }
            /*} else
            {
                throw new Exception("Can only verify ECC B-233 signatures currently!");
            }*/
        }

        public bool VerifyChildCertificate(WiiCertificate child)
        {
            // verify the child certificate has the issuer we expect
            string expectedIssuer = Subject == "Root" ? Subject : Issuer + "-" + Subject;
            if (child.Issuer != expectedIssuer)
                return false;
            // verify the signature of the child certificate's data
            return VerifySignature(child.GetSignableBuffer(), child.issuerSignatureData!);
        }

        public WiiCertificate(Stream stream)
        {
            // read issuer information
            issuerSignatureType = (WiiSignatureType)stream.ReadUInt32BE();
            if (issuerSignatureType == WiiSignatureType.ECCB233)
            {
                issuerSignatureData = stream.ReadBytes(0x3C);
                stream.Seek(0x40, SeekOrigin.Current); // skip padding
            }
            else if (issuerSignatureType == WiiSignatureType.RSA2048)
            {
                issuerSignatureData = stream.ReadBytes(0x100);
                stream.Seek(0x3C, SeekOrigin.Current); // skip padding
            }
            else if (issuerSignatureType == WiiSignatureType.RSA4096)
            {
                issuerSignatureData = stream.ReadBytes(0x200);
                stream.Seek(0x3C, SeekOrigin.Current); // skip padding
            }
            else
            {
                throw new Exception($"Signature type \"{issuerSignatureType:X8}\" is unknown and unsupported!");
            }
            issuerStringBytes = stream.ReadBytes(0x40);
            Issuer = Encoding.ASCII.GetString(issuerStringBytes).Trim('\0');

            // read current key information
            keyType = (WiiKeyType)stream.ReadUInt32BE();
            subjectStringBytes = stream.ReadBytes(0x40);
            Subject = Encoding.ASCII.GetString(subjectStringBytes).Trim('\0');
            KeyID = stream.ReadUInt32BE();
            if (keyType == WiiKeyType.ECCB233)
            {
                keyData = stream.ReadBytes(0x3C);
                stream.Seek(0x3C, SeekOrigin.Current); // skip padding
            } else if (keyType == WiiKeyType.RSA2048)
            {
                keyData = stream.ReadBytes(0x100);
                keyExponent = stream.ReadUInt32BE();
                stream.Seek(0x34, SeekOrigin.Current); // skip padding
            }
            else if (keyType == WiiKeyType.RSA4096)
            {
                keyData = stream.ReadBytes(0x200);
                keyExponent = stream.ReadUInt32BE();
                stream.Seek(0x34, SeekOrigin.Current); // skip padding
            }
        }

        public WiiCertificate(byte[] buffer) : this(new MemoryStream(buffer))
        {

        }

        internal WiiCertificate()
        {

        }
    }
}
