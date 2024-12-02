using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math;

namespace WiiSigVerifySharp
{
    public class WiiUtilities
    {
        static internal bool VerifyECDSASha1(byte[] public_key, byte[] buffer, byte[] signature)
        {
            X9ECParameters xParams = ECNamedCurveTable.GetByName("sect233r1");
            ECDomainParameters ecParams = new ECDomainParameters(xParams);
            ECPoint ecPoint = xParams.Curve.CreatePoint(new BigInteger(public_key, 0, 0x1E),
                new BigInteger(public_key, 0x1E, 0x1E));
            ECPublicKeyParameters publicKey = new ECPublicKeyParameters(ecPoint, ecParams);
            ISigner signer = SignerUtilities.GetSigner("SHA-1withPLAIN-ECDSA");
            signer.Init(false, publicKey);
            signer.BlockUpdate(buffer);
            return signer.VerifySignature(signature);
        }

        static internal bool VerifyRSASha1(uint exponent, byte[] public_key, byte[] buffer, byte[] signature)
        {
            RsaKeyParameters publicKey = new RsaKeyParameters(false,
                new BigInteger(1, public_key, true), new BigInteger(BitConverter.GetBytes(exponent), false));
            ISigner signer = SignerUtilities.GetSigner("SHA-1withRSA");
            signer.Init(false, publicKey);
            signer.BlockUpdate(buffer);
            return signer.VerifySignature(signature);
        }

        static public byte[] DWC_Base64Decode(string input)
        {
            string transformedInput = input.Replace('.', '+').Replace('-', '/').Replace('*', '=');
            return Convert.FromBase64String(transformedInput);
        }
    }
}
