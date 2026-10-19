using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using Atlas;
using Atlas.Binja;

internal static class TypeMapsChecks {
    private const ulong Start = 0x140001000;
    private static readonly ulong[] Fixups = [Start + 768, Start + 832, Start + 896,
        Start + 960, Start + 1024, Start + 4096, Start + 1088];

    internal static void Run() {
        foreach (int width in new[] { 1, 2, 4 }) {
            byte[] external = Map(true, width);
            byte[] proxy = Map(false, width);
            var image = Image(external, proxy);
            var header = ReadyToRun.Read(image);
            var extraction = Extract(image, Fixups);
            var metadata = extraction.Metadata;
            var maps = extraction.Maps;
            var publication = extraction.Signatures;
            var decoded = extraction.TypeMaps;
            Check(decoded.External.Groups.Length == 3 && decoded.Proxy.Groups.Length == 3, "Group records lost.");
            Check(decoded.External.Entries.Length == 2 && decoded.Proxy.Entries.Length == 2, "Mapping records lost.");
            Check(decoded.External.Bytes.SequenceEqual(external), "Source bytes changed.");

            var valid = decoded.External.Groups[0];
            var invalid = decoded.External.Groups[1];
            var empty = decoded.External.Groups[2];
            Check(valid.Vertex == 64 && valid.Length == 2 && valid.TableOffset == 66 && valid.HashMask == 255,
                "Group coordinates changed.");

            Check(!invalid.IsValid && invalid.State == 0 && invalid.ThrowingStub == Fixups[5]
                && invalid.ThrowingStubFixup == 5 && invalid.Length == 3 && invalid.Entries.Count == 0,
                "Invalid group lost its throwing stub.");

            Check(empty.IsValid && empty.Entries.Count == 0, "Empty valid group changed state.");
            Check(decoded.ThrowingStubs.Length == 2
                && ReferenceEquals(decoded.ThrowingStubs[0].Map, decoded.External)
                && ReferenceEquals(decoded.ThrowingStubs[1].Map, decoded.Proxy)
                && decoded.ThrowingStubs[0].GroupIndex == 1 && decoded.ThrowingStubs[1].GroupIndex == 1,
                "Function consumers lost a compiler-invalid group or included a valid group.");

            Check(decoded.External.Entries[0].Name == "é😀" && decoded.External.Entries[0].Vertex == 160
                && decoded.External.Entries[1].Name == "alpha" && decoded.External.Entries[1].Vertex == 40,
                "Forward/backward name records or Unicode changed.");

            Check(decoded.External.Entries[1].Length == 7 && decoded.External.Entries[1].NameBytes.Equals(new IndexRange(41, 5)),
                "String byte provenance lost.");

            Check(extraction.ExternalMapGroupTypeAt(0).Equals(extraction.ProxyMapGroupTypeAt(0))
                && extraction.ExternalMapTargetTypeAt(0).Equals(extraction.ProxyMapTargetTypeAt(0))
                && extraction.ProxyMapSourceTypeAt(0).Address == Fixups[2], "Runtime references have different owners.");

            foreach (var type in extraction.Types.Types) {
                Check((type.Evidence & (TypeEvidence.ExternalTypeMap | TypeEvidence.ProxyTypeMap)) != 0,
                    "A map-only type lost its evidence.");
            }

            using var output = new MemoryStream();
            using (var writer = new Utf8JsonWriter(output))
                TypeMapsOutput.Write(writer, "fixture", extraction);
            using var json = JsonDocument.Parse(output.ToArray());
            var externalJson = json.RootElement.GetProperty("external");
            Check(externalJson.GetProperty("status").GetString() == "decoded"
                && externalJson.GetProperty("mapping_count").GetInt32() == 2
                && externalJson.GetProperty("groups")[1].GetProperty("throwing_stub").GetUInt64() == Fixups[5],
                "CLI output omits map state or relationships.");

            // Two buckets can point at the same payload so we keep both records
            byte[] shared = (byte[])proxy.Clone();
            int row = 67 + 2 * width;
            Signed(shared, row + 7, 40 - (row + 7));
            var sharedImage = Image(external, shared);
            var sharedTypes = new MethodTables();
            var sharedMaps = new TypeMaps(sharedImage, ReadyToRun.Read(sharedImage), Fixups, sharedTypes, default);
            Check(sharedMaps.Proxy.Entries.Length == 2 && sharedMaps.Proxy.Entries[0].Vertex == 40
                && sharedMaps.Proxy.Entries[1].Vertex == 40, "Shared vertices were collapsed.");
            var sharedPrepared = new PreparedAnalysis(sharedImage, ReadyToRun.Read(sharedImage), new MetadataBuilder(default, 7), new ReflectionMaps(), Fixups);
            var sharedEvidence = AnalysisEvidence.Read(sharedPrepared, sharedImage.ImageBase);
            var sharedTag = sharedEvidence.Tags.Single(tag => tag.Address == Start + 320 + 40);
            string[] sharedLines = sharedTag.Text.Split('\n');
            Check(sharedLines.Length == 2 && sharedLines[0] == sharedLines[1], "Shared metadata tag lines were lost or reordered.");

            byte[] escaped = (byte[])external.Clone();
            Encoding.UTF8.GetBytes("\\\0\r\nx").CopyTo(escaped, 41);
            escaped[67 + 2 * width + 6] = 0xCE; // NativeAOT name hash 0x6DD420CE.
            var escapedImage = Image(escaped, proxy);
            var escapedPrepared = new PreparedAnalysis(escapedImage, ReadyToRun.Read(escapedImage), new MetadataBuilder(default, 7), new ReflectionMaps(), Fixups);
            var escapedTag = AnalysisEvidence.Read(escapedPrepared, escapedImage.ImageBase).Tags
                .Single(tag => tag.Address == Start + 64 + 40);
            Check(escapedTag.Text.Contains(@"name=\\\0\r\nx", StringComparison.Ordinal), "Native tag escaping changed.");

            Mutate(external, proxy, bytes => bytes[65] = 4, "Unsupported type map state");
            Mutate(external, proxy, bytes => bytes[64] = 126, "CommonFixups");
            Mutate(external, proxy, bytes => bytes[41] = 0xFF, "UTF");
            Mutate(external, proxy, bytes => {
                bytes[40] = 0xE9;
                bytes[41] = 3;
            }, "Truncated");
            Mutate(external, proxy, bytes => bytes[180] = 0xFE, "CommonFixups");
            Mutate(external, proxy, bytes => bytes[66] |= 3, "NativeHashtable");
            Mutate(external, proxy, bytes => bytes[67 + 2 * width] ^= 1, "name hash");
            Mutate(external, proxy, bytes => bytes[67 + 2 * width + 1] = 0xFF, "NativeFormat");
            Mutate(external, proxy, bytes => bytes[1] = 0, "bucket");
            Mutate(external, proxy, bytes => Signed(bytes, 2 + 2 * width, int.MinValue), "vertex");
            Reject(() => Extract(Image(external[..68], proxy), Fixups), "Truncated NativeHashtable");

            Reject(() => Extract(Image(external, proxy), [.. Fixups[..1], 0, .. Fixups[2..]]), "CommonFixups");
            Reject(() => Extract(Image(external, proxy), [.. Fixups[..5], 1, Fixups[6]]), "executable");
            var wrongGroupHash = Image(external, proxy);
            wrongGroupHash.FileData[512 + 768 + 20] ^= 1;
            Reject(() => Extract(new PeImage(wrongGroupHash.FileData), Fixups), "group hash");
            var wrongSourceHash = Image(external, proxy);
            wrongSourceHash.FileData[512 + 896 + 20] ^= 1;
            Reject(() => Extract(new PeImage(wrongSourceHash.FileData), Fixups), "source hash");

            using var cancelled = new CancellationTokenSource();
            cancelled.Cancel();
            try {
                _ = new Extraction(image, header, new MetadataBuilder(default, 7), new ReflectionMaps(), Fixups,
                    ExtractionStage.RuntimeTypes, cancelled.Token);
                throw new Exception("Cancelled extraction succeeded.");
            } catch (OperationCanceledException) {
                Check(ReferenceEquals(publication, metadata.PublishedSignatures), "Cancellation published metadata.");
            }

            // Fail after map roots are discovered because the callers graph needs remain intact
            byte[] lateFailure = (byte[])proxy.Clone();
            lateFailure[64] = 126;
            var damaged = Image(external, lateFailure);
            Reject(() => _ = new Extraction(damaged, ReadyToRun.Read(damaged), new MetadataBuilder(default, 7), new ReflectionMaps(),
                Fixups, ExtractionStage.RuntimeTypes), "CommonFixups");
            Check(ReferenceEquals(publication, metadata.PublishedSignatures) && maps.TypeEntries.IsEmpty,
                "Failed extraction published partial type metadata.");

            var prepared = new PreparedAnalysis(image, header, new MetadataBuilder(default, 7), new ReflectionMaps(), Fixups);
            var evidence = AnalysisEvidence.Read(prepared, image.ImageBase);
            const ulong delta = 0x10000000;
            var rebased = AnalysisEvidence.Read(prepared, image.ImageBase + delta);
            Check(rebased.References.ToHashSet().SetEquals(evidence.References.Select(reference =>
                new AnalysisReference(reference.From + delta, reference.To + delta))), "Map references did not rebase.");
            Check(evidence.References.Contains(new(Start + 64 + 180, Fixups[5]))
                && evidence.Tags.Any(tag => tag.Text.Contains("name=é😀", StringComparison.Ordinal)),
                "Host evidence lost invalid stubs or Unicode mappings.");
        }

        var absentImage = Image([], []);
        var absent = Extract(absentImage, Fixups);
        Check(!absent.TypeMaps.External.Present && absent.TypeMaps.External.Groups.IsEmpty,
            "Absent map acquired records.");
        byte[] emptySection = (byte[])absentImage.FileData.Clone();
        BinaryPrimitives.WriteInt32LittleEndian(emptySection.AsSpan(528), (int)RtrSectionId.ExternalTypeMap);
        var emptyMap = Extract(new PeImage(emptySection), Fixups).TypeMaps.External;
        Check(emptyMap.Present && emptyMap.Bytes.IsEmpty && emptyMap.Groups.IsEmpty && emptyMap.HashMask == 0,
            "Zero-length section became absent or acquired records.");
        CheckNestedBuckets();
        var resources = new Extraction(absentImage, ReadyToRun.Read(absentImage), new MetadataBuilder(default, 7),
            new ReflectionMaps(), [], ExtractionStage.Resources);
        try {
            _ = resources.TypeMaps;
            throw new Exception("Unrequested type maps were accessible.");
        } catch (InvalidOperationException) {
        }

        Check(CommandPlan.For("typemaps")!.Stages == ExtractionStage.RuntimeTypes, "Wrong CLI prerequisites.");
        Console.WriteLine("Type maps: nested offsets, widths, Unicode, shared vertices, states, map-only roots, invalid inputs, publication, CLI and rebased host evidence passed.");
    }

    private static Extraction Extract(PeImage image, ulong[] fixups) => new(image, ReadyToRun.Read(image),
        new MetadataBuilder(default, 7), new ReflectionMaps(), fixups, ExtractionStage.RuntimeTypes);

    private static void CheckNestedBuckets() {
        foreach (int width in new[] { 1, 2, 4 }) {
            byte[] data = new byte[80];
            const int offset = 16;
            data[offset] = (byte)(4 | (width == 1 ? 0 : width == 2 ? 1 : 2));
            int indexOrigin = offset + 1;
            for (int bucket = 0; bucket < 3; ++bucket) {
                uint boundary = (uint)(3 * width + bucket * 6);
                for (int part = 0; part < width; ++part)
                    data[indexOrigin + bucket * width + part] = (byte)(boundary >> (8 * part));
            }

            int row = indexOrigin + 3 * width;
            data[row] = 0xEE;
            Signed(data, row + 1, 8 - (row + 1));
            data[row + 6] = 0x11;
            Signed(data, row + 7, 72 - (row + 7));
            var table = new NativeTable(data, offset);
            Check(table.BucketMask == 1 && table.MoveNext() && table.Bucket == 0
                && table.LowHash == 0xEE && table.Vertex == 8, "Nested bucket 0 coordinates changed.");
            Check(table.MoveNext() && table.Bucket == 1 && table.LowHash == 0x11 && table.Vertex == 72
                && !table.MoveNext(), "Nested bucket 1 coordinates or hash reset changed.");
        }
    }

    private static void Mutate(byte[] external, byte[] proxy, Action<byte[]> mutate, string error) {
        byte[] changed = (byte[])external.Clone();
        mutate(changed);
        Reject(() => Extract(Image(changed, proxy), Fixups), error);
    }

    private static void Reject(Action action, string message) {
        try {
            action();
        } catch (InvalidDataException error) when (error.Message.Contains(message, StringComparison.OrdinalIgnoreCase)
            && error.Message.Contains("section 34", StringComparison.Ordinal)) {
            return;
        }

        throw new Exception($"Expected type map error containing '{message}'.");
    }

    private static byte[] Map(bool external, int width) {
        byte[] bytes = new byte[224];
        Table(bytes, 0, width, [(0x11, 64), (0x22, 180), (0x33, 200)]);
        bytes[64] = 0; // Group fixup 0, valid state 1
        bytes[65] = 2;
        Table(bytes, 66, width, external ? [(0x9C, 160), (0xC1, 40)] : [(0x55, 40), (0x55, 160)]);
        if (external) {
            bytes[40] = 10;
            Encoding.UTF8.GetBytes("alpha").CopyTo(bytes, 41);
            bytes[46] = 2;
            bytes[160] = 12;
            Encoding.UTF8.GetBytes("é😀").CopyTo(bytes, 161);
            bytes[167] = 2;
        } else {
            bytes[40] = 4;
            bytes[41] = 2;
            bytes[160] = 12;
            bytes[161] = 2;
        }

        bytes[180] = 6; // Group fixup 3, invalid state 0, throwing stub fixup 5
        bytes[181] = 0;
        bytes[182] = 10;
        bytes[200] = 8;
        bytes[201] = 2;
        Table(bytes, 202, width, []);
        return bytes;
    }

    private static void Table(byte[] bytes, int offset, int width, (byte Hash, int Vertex)[] entries) {
        bytes[offset] = width == 1 ? (byte)0 : width == 2 ? (byte)1 : (byte)2;
        int start = 2 * width;
        int end = start + 6 * entries.Length;
        for (int i = 0; i < width; ++i) {
            bytes[offset + 1 + i] = (byte)(start >> (8 * i));
            bytes[offset + 1 + width + i] = (byte)(end >> (8 * i));
        }

        int row = offset + 1 + start;
        foreach (var entry in entries) {
            bytes[row++] = entry.Hash;
            Signed(bytes, row, entry.Vertex - row);
            row += 5;
        }
    }

    private static void Signed(byte[] bytes, int offset, int value) {
        bytes[offset] = 15;
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(offset + 1), value);
    }

    private static PeImage Image(byte[] external, byte[] proxy) {
        byte[] data = new byte[1216];
        "RTR\0"u8.CopyTo(data);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(4), 16);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(12), external.Length == 0 ? (ushort)1 : (ushort)2);
        data[14] = 24;
        data[15] = 1;
        if (external.Length == 0) {
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(16), 325);
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20), 1);
            BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(24), Start + 64);
            BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(32), Start + 64);
        }

        for (int i = 0; i < 2 && external.Length != 0; ++i) {
            var row = data.AsSpan(16 + i * 24);
            BinaryPrimitives.WriteUInt32LittleEndian(row, (uint)(340 + i));
            BinaryPrimitives.WriteUInt32LittleEndian(row[4..], 1);
            BinaryPrimitives.WriteUInt64LittleEndian(row[8..], Start + (uint)(64 + i * 256));
            BinaryPrimitives.WriteUInt64LittleEndian(row[16..], Start + (uint)(64 + i * 256 + (i == 0 ? external.Length : proxy.Length)));
        }

        external.CopyTo(data, 64);
        proxy.CopyTo(data, 320);
        uint[] hashes = [0x11, 0x44, 0x55, 0x22, 0x33, 0x155];
        for (int i = 0; i < hashes.Length; ++i) {
            var type = data.AsSpan(768 + i * 64);
            BinaryPrimitives.WriteUInt32LittleEndian(type, 0x50000000);
            BinaryPrimitives.WriteUInt32LittleEndian(type[4..], 24);
            BinaryPrimitives.WriteUInt32LittleEndian(type[20..], hashes[i]);
            BinaryPrimitives.WriteInt32LittleEndian(type[24..], -24 - i * 64);
        }

        data[1152] = 0xC3;
        byte[] pe = PeFixture.Create(data, ".rdata", 0x40000040).FileData;
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(70), 2);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(144), 0x2040);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(336), 1152);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(344), 1152);
        ".text"u8.CopyTo(pe.AsSpan(368));
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(376), 64);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(380), 0x2000);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(384), 64);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(388), 512 + 1152);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(404), 0x60000020);
        return new PeImage(pe);
    }

    private static void Check(bool condition, string error) {
        if (!condition)
            throw new Exception(error);
    }
}
