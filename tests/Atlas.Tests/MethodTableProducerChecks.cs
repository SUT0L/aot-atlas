using System.Buffers.Binary;
using System.Diagnostics;
using Atlas;

internal static class MethodTableProducerChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        foreach (string probe in binaries) {
            var image = new PeImage(File.ReadAllBytes(probe));
            var rtr = ReadyToRun.Read(image);

            var section = rtr.Find(313);
            var metadata = new MetadataBuilder(
                image.FileMemory(section.Start, checked((int)section.Length)),
                rtr.MetadataHandleBits, rtr.Major < 10);
            metadata.ReadDefinitions();

            var maps = new ReflectionMaps();
            var commonFixups = RuntimeTables.Fixups(image, rtr.Find(308));
            maps.Read(image, rtr, metadata, commonFixups);

            var extraction = new Extraction(image, rtr, metadata, maps, commonFixups);
            var hydrated = extraction.Hydrated;
            var types = extraction.Types;

            var start = new ProcessStartInfo(Path.GetFullPath(probe)) {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(start)!;
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            Check(process.ExitCode == 0);

            string[] lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            Check(lines.Length == 9);

            foreach (string line in lines) {
                string[] parts = line.Split('|');
                Check(parts.Length == 5);
                ulong va = image.ImageBase + Convert.ToUInt64(parts[1], 16);
                var type = types.Types[types.Index[va]];
                Check(type.IsValueType && type.ValueSize == uint.Parse(parts[2]));

                byte[] live = Convert.FromHexString(parts[3]);
                var bytes = va >= hydrated.Start && va - hydrated.Start < (ulong)hydrated.Length
                    ? hydrated.Bytes.Slice(checked((int)(va - hydrated.Start)), 24)
                    : image.FileSpan(va, 24);
                Check(bytes[..8].SequenceEqual(live.AsSpan(0, 8)) && bytes[16..].SequenceEqual(live.AsSpan(16)));

                ulong baseAddress = Convert.ToUInt64(parts[4], 16);
                ulong related = BinaryPrimitives.ReadUInt64LittleEndian(bytes[8..]);
                ulong expectedRelated = related == 0 ? 0 : related - image.ImageBase + baseAddress;
                Check(BinaryPrimitives.ReadUInt64LittleEndian(live.AsSpan(8)) == expectedRelated);
            }

            Console.WriteLine($"{probe}: 9 live MethodTable headers, relocated pointers and value sizes match.");

        }
    }

    private static void Check(bool condition) {
        if (!condition)
            throw new Exception("Runtime MethodTable disagrees with its live producer.");
    }
}
