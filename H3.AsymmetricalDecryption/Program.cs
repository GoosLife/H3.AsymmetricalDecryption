using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace H3.AsymmetricalDecryption
{
	internal class Program
	{
		static void Main(string[] args)
		{
			Console.WriteLine("Run benchmarks? (y/N)");
			string input = Console.ReadLine();
			if (input.ToLower() == "y")
			{
				Benchmark();
				return;
			}

			using RSA rsa = RSA.Create();

			// Try to get key from XML file (if exists)
			if (System.IO.File.Exists("private_key.xml"))
			{
				rsa.FromXmlString(System.IO.File.ReadAllText("private_key.xml"));
			}
			// Else, generate a new key and save it to XML file
			else
			{
				rsa.KeySize = 2048;
				System.IO.File.WriteAllText("private_key.xml", rsa.ToXmlString(true));
			}

			var publicKey = rsa.ExportRSAPublicKey();
			var privateKey = rsa.ExportRSAPrivateKey();

			// Get exponent and modulus from public key
			RSAParameters rsaParams = rsa.ExportParameters(false);
			byte[]? exponent = rsaParams.Exponent;
			byte[]? modulus = rsaParams.Modulus;

			// Get D, DP, DQ, InverseQ, P and Q from private key
			rsaParams = rsa.ExportParameters(true);
			var d = rsaParams.D;
			var dp = rsaParams.DP;
			var dq = rsaParams.DQ;
			var inverseQ = rsaParams.InverseQ;
			var p = rsaParams.P;
			var q = rsaParams.Q;

			var data = new byte[] { 1, 2, 3, 4, 5 };

			// Make console text bold
			Console.WriteLine("");
			// Make it not bold
			Console.WriteLine("\x1B[22m");
			Console.WriteLine(
				$"\u001b[1m Public data:\x1b[22m\n" +
				$"\tExponent: {ToHex(exponent)}\n" +
				$"\tModulus: {ToHex(modulus)}\n" +
				$"\u001b[1m Private data:\x1b[22m\n" +
				$"\tD: {ToHex(d)}\n" +
				$"\tDP: {ToHex(dp)}\n" +
				$"\tDQ: {ToHex(dq)}\n" +
				$"\tInverseQ: {ToHex(inverseQ)}\n" +
				$"\tP: {ToHex(p)}\n" +
				$"\tQ: {ToHex(q)}\n" +
				"Enter data to decrypt: ");

			string encryptedData = Console.ReadLine();

			// Convert Hex string (with dash separator) to byte array
			byte[] encryptedDataBytes = encryptedData.Split('-').Select(x => Convert.ToByte(x, 16)).ToArray();

			// Decrypt encrypted data bytes
			byte[] decryptedData = rsa.Decrypt(encryptedDataBytes, RSAEncryptionPadding.OaepSHA256);

			// Write the decrypted data to console as plaintext
			Console.WriteLine(Encoding.UTF8.GetString(decryptedData));
		}

		static string ToHex(byte[] data)
		{
			return BitConverter.ToString(data);
		}

		static void Benchmark()
		{
			Console.Clear();
			Console.WriteLine("Running benchmarks...\n");
			int[] keySizes = new int[] { 1024, 2048, 3072, 4096, 3072, 2048, 1024 };

			foreach (int keySize in keySizes)
			{
				PrintTableHeader();
				BenchmarkKeyGeneration(keySize);
				BenchmarkEncryption(keySize);
				BenchmarkDecryption(keySize);
			}

			Console.WriteLine("Press any key to exit...");
			Console.ReadKey();
		}

		static void PrintTableHeader()
		{
			// Set border color for header
			Console.ForegroundColor = ConsoleColor.Magenta;
			Console.WriteLine("+-------------------+-----------------+------------+");

			// Set header text color
			Console.Write("| ");
			Console.ForegroundColor = ConsoleColor.Yellow;
			Console.Write("Operation         ");
			Console.ForegroundColor = ConsoleColor.Magenta;
			Console.Write("| ");
			Console.ForegroundColor = ConsoleColor.Yellow;
			Console.Write("Key Size (bits) ");
			Console.ForegroundColor = ConsoleColor.Magenta;
			Console.Write("| ");
			Console.ForegroundColor = ConsoleColor.Yellow;
			Console.Write("Time (ms)  ");
			Console.ForegroundColor = ConsoleColor.Magenta;
			Console.Write("|\n");

			// Continue border color for header
			Console.ForegroundColor = ConsoleColor.Magenta;
			Console.WriteLine("+-------------------+-----------------+------------+");

			Console.ResetColor(); // Reset to default color
		}

		static void PrintTableRow(string operation, int keySize, long time)
		{
			// Set border color for rows
			Console.ForegroundColor = ConsoleColor.Magenta;
			Console.Write("| ");

			// Set operation name color
			Console.ForegroundColor = ConsoleColor.Cyan;
			Console.Write($"{operation.PadRight(17)} ");

			// Continue border color for row
			Console.ForegroundColor = ConsoleColor.Magenta;
			Console.Write("| ");

			// Set key size and time color
			Console.ForegroundColor = ConsoleColor.White;
			Console.Write($"{keySize.ToString().PadRight(15)} ");

			// Continue border color for row
			Console.ForegroundColor = ConsoleColor.Magenta;
			Console.Write("| ");

			// Set time color differently if you want
			Console.ForegroundColor = ConsoleColor.Green;
			Console.Write($"{time.ToString().PadRight(10)} ");

			Console.ForegroundColor = ConsoleColor.Magenta;
			Console.Write("|\n");

			// Continue border color for row
			Console.WriteLine("+-------------------+-----------------+------------+");

			Console.ResetColor(); // Reset to default color
		}

		static void BenchmarkKeyGeneration(int keySize)
		{
			Stopwatch stopwatch = Stopwatch.StartNew();
			for (int i = 0; i < 1000000; i++)
			{
				using (RSA rsa = RSA.Create(keySize)) { }
			}
			stopwatch.Stop();
			PrintTableRow("Key Generation", keySize, stopwatch.ElapsedMilliseconds);
		}

		static void BenchmarkEncryption(int keySize)
		{
			byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Sample data for encryption");
			Stopwatch stopwatch = new Stopwatch();

			using (RSA rsa = RSA.Create(keySize))
			{
				stopwatch.Start();
				for (int i = 0; i < 10000; i++)
				{
					byte[] encryptedData = rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);
				}
				stopwatch.Stop();
			}

			PrintTableRow("Encryption", keySize, stopwatch.ElapsedMilliseconds);
		}

		static void BenchmarkDecryption(int keySize)
		{
			byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Sample data for encryption");
			byte[] encryptedData;

			using (RSA rsa = RSA.Create(keySize))
			{
				encryptedData = rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);

				Stopwatch stopwatch = new Stopwatch();

				stopwatch.Start();
				for (int i = 0; i < 10000; i++)
				{
					byte[] decryptedData = rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);
				}
				stopwatch.Stop();
				PrintTableRow("Decryption", keySize, stopwatch.ElapsedMilliseconds);
			}

		}
	}
}
