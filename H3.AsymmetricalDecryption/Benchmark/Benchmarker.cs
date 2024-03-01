using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace H3.AsymmetricalDecryption.Benchmark
{
	internal static class Benchmarker
	{
		public static void Benchmark()
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

		private static void PrintTableHeader()
		{
			// Set border color for header
			Console.ForegroundColor = ConsoleColor.Magenta;
			Console.WriteLine("+-------------------+-----------------+----------------+------------+");

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
			Console.Write("Avg time (ms)  ");
			Console.ForegroundColor = ConsoleColor.Magenta;
			Console.Write("| ");
			Console.ForegroundColor = ConsoleColor.Yellow;
			Console.Write("Time (ms)  ");
			Console.ForegroundColor = ConsoleColor.Magenta;
			Console.Write("|\n");

			// Continue border color for header
			Console.ForegroundColor = ConsoleColor.Magenta;
			Console.WriteLine("+-------------------+-----------------+----------------+------------+");

			Console.ResetColor(); // Reset to default color
		}

		private static void PrintTableRow(string operation, int keySize, long time, int iterations)
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
			Console.Write($"{(((long)time / iterations)).ToString().PadLeft(14)} ");

			Console.ForegroundColor = ConsoleColor.Magenta;
			Console.Write("| ");

			// Set time color differently if you want
			Console.ForegroundColor = ConsoleColor.Green;
			Console.Write($"{time.ToString().PadLeft(10)} ");

			Console.ForegroundColor = ConsoleColor.Magenta;
			Console.Write("|\n");

			// Continue border color for row
			Console.WriteLine("+-------------------+-----------------+----------------+------------+");

			Console.ResetColor(); // Reset to default color
		}

		private static void BenchmarkKeyGeneration(int keySize)
		{
			int iterations = 1000000;
			Stopwatch stopwatch = Stopwatch.StartNew();
			for (int i = 0; i < iterations; i++)
			{
				using (RSA rsa = RSA.Create(keySize)) {
					// Print key to console - don't uncomment this, it will make the program take forever to run
					// Console.WriteLine(rsa.ToXmlString(true));
				}
			}
			stopwatch.Stop();
			PrintTableRow("Key Generation", keySize, stopwatch.ElapsedMilliseconds, iterations);
		}

		private static void BenchmarkEncryption(int keySize)
		{
			byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Sample data for encryption");
			Stopwatch stopwatch = new Stopwatch();

			int iterations = 10000;

			using (RSA rsa = RSA.Create(keySize))
			{
				stopwatch.Start();
				for (int i = 0; i < iterations; i++)
				{
					byte[] encryptedData = rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);
				}
				stopwatch.Stop();
			}

			PrintTableRow("Encryption", keySize, stopwatch.ElapsedMilliseconds, iterations);
		}

		private static void BenchmarkDecryption(int keySize)
		{
			byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Sample data for encryption");
			byte[] encryptedData;

			int iterations = 1000;

			using (RSA rsa = RSA.Create(keySize))
			{
				encryptedData = rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);

				Stopwatch stopwatch = new Stopwatch();

				stopwatch.Start();
				for (int i = 0; i < iterations; i++)
				{
					byte[] decryptedData = rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);
				}
				stopwatch.Stop();
				PrintTableRow("Decryption", keySize, stopwatch.ElapsedMilliseconds, iterations);
			}

		}
	}
}
