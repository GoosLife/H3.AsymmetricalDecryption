using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace H3.AsymmetricalDecryption.Encryption
{
	internal class RSAEncryptor
	{
		private static readonly Lazy<RSAEncryptor> lazy = new Lazy<RSAEncryptor>(() => new RSAEncryptor());
		public static RSAEncryptor Instance { get { return lazy.Value; } }

		private RSA _rsa;

		private byte[] exponent;
		private byte[] modulus;
		private byte[] d;
		private byte[] dp;
		private byte[] dq;
		private byte[] inverseQ;
		private byte[] p;
		private byte[] q;

		private RSAEncryptor()
		{
			_rsa = RSA.Create();

			// Try to get key from XML file (if exists)
			if (System.IO.File.Exists("private_key.xml"))
			{
				_rsa.FromXmlString(System.IO.File.ReadAllText("private_key.xml"));
			}
			// Else, generate a new key and save it to XML file
			else
			{
				_rsa.KeySize = 2048;
				System.IO.File.WriteAllText("private_key.xml", _rsa.ToXmlString(true));
			}

			try
			{
				// Get exponent and modulus from public key
				RSAParameters rsaParams = _rsa.ExportParameters(false);
				exponent = rsaParams.Exponent!;
				modulus = rsaParams.Modulus!;

				// Get D, DP, DQ, InverseQ, P and Q from private key
				rsaParams = _rsa.ExportParameters(true);
				d = rsaParams.D!;
				dp = rsaParams.DP!;
				dq = rsaParams.DQ!;
				inverseQ = rsaParams.InverseQ!;
				p = rsaParams.P!;
				q = rsaParams.Q!;
			}
			catch (Exception ex)
			{
				throw new Exception("Error while getting RSA parameters", ex);
			}
		}

		public override string ToString()
		{
			return
				$"\u001b[1mPublic data:\x1b[22m\n" +
				$"\tExponent: {BitConverter.ToString(exponent)}\n" +
				$"\tModulus: {BitConverter.ToString(modulus)}\n" +
				$"\u001b[1mPrivate data:\x1b[22m\n" +
				$"\tD: {BitConverter.ToString(d)}\n" +
				$"\tDP: {BitConverter.ToString(dp)}\n" +
				$"\tDQ: {BitConverter.ToString(dq)}\n" +
				$"\tInverseQ: {BitConverter.ToString(inverseQ)}\n" +
				$"\tP: {BitConverter.ToString(p)}\n" +
				$"\tQ: {BitConverter.ToString(q)}\n";
		}

		public byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
		{
			return _rsa.Decrypt(data, padding);
		}
	}
}
