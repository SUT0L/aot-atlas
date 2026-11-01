using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Atlas;

internal static class MarshallingChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        foreach (string binary in binaries) {
            var image = new PeImage(File.ReadAllBytes(binary));
            var header = ReadyToRun.Read(image);

            var section = header.Find(313);
            var metadata = MetadataBuilder.FromImage(image, header);
            metadata.ReadDefinitions();

            var fixups = RuntimeTables.Fixups(image, header.Find(308));
            var maps = new ReflectionMaps();
            maps.Read(image, header, metadata, fixups);

            var extraction = new Extraction(image, header, metadata, maps, fixups);

            using var process = Process.Start(new ProcessStartInfo(Path.GetFullPath(binary)) {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            })!;
            string runtime = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            Assert(process.ExitCode == 0);

            string[] lines = runtime.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            Assert(lines.Length == 8);

            NativeStruct[] records = new NativeStruct[2];
            int fields = 0;

            foreach (string line in lines) {
                string[] row = line.Split('|');
                int type = int.Parse(row[1]);
                if (row[0] == "S") {
                    ulong address = image.ImageBase + Convert.ToUInt64(row[2], 16);
                    var record = extraction.Marshalling.Structs.Single(entry => extraction.Types.Types[entry.TypeIndex].Address == address);
                    records[type] = record;
                    Assert(record.Size == uint.Parse(row[3]) && record.Size == uint.Parse(row[4]));
                    Assert(record.SizeSource == (type == 0 ? NativeSizeSource.RuntimeCopy : NativeSizeSource.MethodTable));
                    Assert(record.HasLayoutSize == (type == 1));
                } else {
                    Assert(row[0] == "F");

                    var record = records[type];
                    var entry = CollectionsMarshal.AsSpan(extraction.Marshalling.Fields)
                        .Slice(record.Fields.Start, record.Fields.Count)[fields % 3];
                    string name = System.Text.Encoding.UTF8.GetString(
                        extraction.Marshalling.StructData.Span.Slice(entry.Name.Start, entry.Name.Count));
                    Assert(name == row[2] && entry.Offset == uint.Parse(row[4]));
                    Assert(uint.Parse(row[3]) == (type == 0 ? (uint)(fields % 3) : entry.Offset));
                    ++fields;
                }
            }

            Assert(fields == 6 && records[0].Size == 4 && records[1].Size == 11);
            Assert(extraction.Marshalling.Fields[records[0].Fields.Start + 2].Offset == 8);

            Console.WriteLine($"Marshalling sizes: {Convert.ToHexString(SHA256.HashData(image.FileData)).ToLowerInvariant()} — two live sizes, six offsets, and the auto-layout domain verified.");
        }

        Console.WriteLine("Marshalling sizes: extracted native layouts match the running producer.");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("Marshalling size assertion failed.");
    }
}
