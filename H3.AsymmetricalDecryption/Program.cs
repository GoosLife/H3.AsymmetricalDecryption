using H3.AsymmetricalDecryption.Encryption;
using H3.AsymmetricalDecryption.Benchmark;
using System.Security.Cryptography;
using System.Text;

namespace H3.AsymmetricalDecryption
{
	internal class Program
	{
		static void Main(string[] args)
		{
			string input = "";

			while (input != "3")
			{
				Console.Clear();
				Console.WriteLine("1. Decrypt data");
                Console.WriteLine("2. Run benchmarks");
                Console.WriteLine("3. Exit");

                input = Console.ReadLine();

				if (input.ToLower() == "2")
				{
					Benchmarker.Benchmark();
					continue;
				}

				// Print RSA information
				Console.WriteLine(RSAEncryptor.Instance.ToString());
				Console.WriteLine("Enter data to decrypt (or exit to quit the program): ");

				string encryptedData = Console.ReadLine();

				try
				{
					// Convert Hex string (with dash separator) to byte array
					byte[] encryptedDataBytes = encryptedData.Split('-').Select(x => Convert.ToByte(x, 16)).ToArray();

					// Decrypt encrypted data bytes
					byte[] decryptedData = RSAEncryptor.Instance.Decrypt(encryptedDataBytes, RSAEncryptionPadding.OaepSHA256);

					// Write the decrypted data to console as plaintext
					Console.WriteLine(Encoding.UTF8.GetString(decryptedData));
                    Console.WriteLine("Press any key to continue . . .");
					Console.ReadKey();
                }
				catch (Exception ex)
				{
					Console.WriteLine("Error while decrypting data: " + ex.Message);
                    Console.WriteLine("Please pretend we're logging the error message and not printing it to console");
                }
			}

		}
	}
}
