# WiiSigVerifySharp

Small .NET library to parse and verify signatures and certificates as used in
the Wii, written in C#.

Uses [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography).

Licensed under the MIT license, see LICENSE.txt.

This is not affiliated with or endorsed by Nintendo.

## Usage

The `WiiCertificate` class takes in either a Stream or byte[] buffer containing
a single correctly formatted certificate.

```csharp
FileStream fs = File.OpenRead("certificate.bin");
WiiCertificate cert = new(fs);
Console.WriteLine(cert.Subject);
if (cert.VerifySignature(signedData, signature))
	TrustData(signedData);
```

As the system uses a certificate chain system, you can verify sub-certificates.
The Root certificate as well as MS00000002 (device signing prod) are included
and accessible via the `WiiIssuers` class:

```csharp
WiiCertificate root = WiiIssuers.Root();
WiiCertificate cert = new(ca1);
if (root.VerifyChildCertificate(cert))
	// ... you can trust that the cert was issued by Root ...
```

## TODO

Code clean up, array usage optimisations and cert chain following.
