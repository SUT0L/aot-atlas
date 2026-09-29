using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Atlas;

internal static class MarshallingChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        foreach (int bits in new[] { 7, 8 }) {
            foreach (uint layout in new uint[] { 0, 8, 16, 24 }) {
                foreach (bool retained in new[] { false, true }) {
                    var metadata = new Metadata(new byte[1], bits);
                    if (retained) {
                        metadata.TypeIndex.Add(1, 0);
                        metadata.Types.Add(new MetadataType { Offset = 1, Flags = layout });
                    }

                    var maps = new ReflectionMaps();
                    maps.Types.Add(new TypeMapEntry { MethodTable = 0x140001000, Handle = (0x3AU << (32 - bits)) | 1 });
                    var tables = new MethodTables();
                    tables.Types.Add(new MethodTable { Address = 0x140001000, Flags = 0x48000000, BaseSize = 24, ValuePadding = 4 });
                    bool nativeExtent = retained && layout is 8 or 16;

                    foreach (uint offset in new uint[] { 0, 4, 8 }) {
                        var marshalling = new Marshalling();
                        marshalling.Structs.Add(new NativeStruct { Header = 4, Fields = new IndexRange(0, 1) });
                        marshalling.Fields.Add(new NativeField(default, offset));
                        bool rejected = false;
                        try {
                            marshalling.Bind(tables, metadata, maps, bits == 8);
                        } catch (InvalidDataException) {
                            rejected = true;
                        }
                        Assert(rejected == (nativeExtent && offset > 4));
                        var entry = marshalling.Structs[0];
                        Assert(entry.Size == 4 && entry.HasLayoutSize == nativeExtent);
                        Assert(entry.SizeSource == (nativeExtent ? NativeSizeSource.MethodTable : NativeSizeSource.RuntimeCopy));
                    }

                    var explicitSize = new Marshalling();
                    explicitSize.Structs.Add(new NativeStruct {
                        Header = 5, Size = 4, SizeSource = NativeSizeSource.MarshallingMap, Fields = new IndexRange(0, 1)
                    });
                    explicitSize.Fields.Add(new NativeField(default, 8));
                    bool explicitRejected = false;
                    try {
                        explicitSize.Bind(tables, metadata, maps, bits == 8);
                    } catch (InvalidDataException) {
                        explicitRejected = true;
                    }
                    Assert(explicitRejected);
                }
            }
        }

        foreach (string binary in binaries) {
            var image = new PeImage(File.ReadAllBytes(binary));
            var header = ReadyToRun.Read(image);
            var section = header.Find(313);
            var metadata = new Metadata(image.FileMemory(section.Start, checked((int)section.Length)),
                header.MetadataHandleBits, header.Major < 10);
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
                    string name = System.Text.Encoding.UTF8.GetString(extraction.Marshalling.StructData.Span.Slice(entry.Name.Start, entry.Name.Count));
                    Assert(name == row[2] && entry.Offset == uint.Parse(row[4]));
                    Assert(uint.Parse(row[3]) == (type == 0 ? (uint)(fields % 3) : entry.Offset));
                    ++fields;
                }
            }
            Assert(fields == 6 && records[0].Size == 4 && records[1].Size == 11);
            Assert(extraction.Marshalling.Fields[records[0].Fields.Start + 2].Offset == 8);
            Console.WriteLine($"Marshalling sizes: {Convert.ToHexString(SHA256.HashData(image.FileData)).ToLowerInvariant()} — two live sizes, six offsets, and the auto-layout domain verified.");
        }
        Console.WriteLine("Marshalling sizes: layout identity, missing metadata, and explicit extent failures verified.");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("Marshalling size assertion failed.");
    }
}
