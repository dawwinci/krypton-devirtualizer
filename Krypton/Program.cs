using System;
using System.Linq;
using Krypton.Core;
using Krypton.Pipeline;
using Console = Colorful.Console;

namespace Krypton
{
    internal class Program
    {
        public static Version CurrentVersion = new Version("1.0.0");

        private static void Main(string[] args)
        {
            var logger = new ConsoleLogger();
            Console.Title = $"Krypton - {CurrentVersion}";

            var pauseOnExit =
                !args.Any(q => string.Equals(q, "--no-pause", StringComparison.OrdinalIgnoreCase)) &&
                !string.Equals(Environment.GetEnvironmentVariable("KRYPTON_NO_PAUSE"), "1", StringComparison.Ordinal);

            try
            {
                var inputPath = args.FirstOrDefault(q => !q.StartsWith("--", StringComparison.Ordinal));
                if (string.IsNullOrWhiteSpace(inputPath))
                {
                    logger.Error("Usage: Krypton.exe <input-assembly> [--no-pause]");
                    return;
                }

                var opts = new DevirtualizationOptions(inputPath, logger);
                var ctx = new DevirtualizationCtx(opts);
                var devirtualizer = new Devirtualizer(ctx);
                devirtualizer.Devirtualize();
                devirtualizer.Save();
            }
            finally
            {
                if (pauseOnExit)
                {
                    Console.WriteLine();
                    Console.WriteLine("Press any key to close...");
                    Console.ReadKey(intercept: true);
                }
            }
        }
    }
}
