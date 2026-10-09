using System.Buffers.Binary;
using Atlas;

internal static class RtrFormatChecks {
    internal static void Run() {
        var versions = new (
            ushort Major, ushort Minor, int HandleBits, bool Legacy, bool Canonical,
            bool Async, bool Lengths, int GcVersion
        )[] {
            (9, 1, 8, true, true, false, false, 2),
            (10, 1, 8, false, true, false, false, 3),
            (12, 0, 7, false, true, false, false, 4),
            (16, 0, 7, false, false, false, false, 4),
            (18, 4, 7, false, false, true, true, 4),
            (18, 5, 7, false, false, true, true, 4)
        };

        foreach (var expected in versions) {
            var header = ReadyToRun.Read(Image(expected.Major, expected.Minor, expected.Lengths));
            var format = header.Format;

            Assert(format.Major == expected.Major && format.Minor == expected.Minor);
            Assert(format.MethodGcVersion == expected.GcVersion);
            Assert(header.MetadataHandleBits == expected.HandleBits && format.MetadataHandleBits == expected.HandleBits);
            Assert(format.LegacyTypeLayout == expected.Legacy && format.LegacyMetadataConstants == expected.Legacy);
            Assert(format.HasPointersFlag == (expected.Legacy ? 0x00200000U : 0x01000000U));
            Assert(format.UniversalCanonicalMethods == expected.Canonical
                && format.OrdinalFields == expected.Canonical
                && format.AsyncMethodVariants == expected.Async);
            Assert(format.InstanceConstrainedMethods == (expected.Major >= 16));
            Assert(header.EmbeddedDehydrationLength == expected.Lengths
                && format.MaskedGenericMethodTokens == expected.Lengths);
            Assert(format.InvokeMapFlags(MapFormat.Legacy) == 0x70FF && format.FieldMapFlags(MapFormat.Legacy) == 0xEF);
            Assert(format.InvokeMapFlags(MapFormat.Metadata) == (expected.Canonical ? 0x70FB : 0x70BB));
            Assert(format.FieldMapFlags(MapFormat.Metadata) == (expected.Canonical ? 0xE7 : 0xE3));

            Assert(header.Sections.Length == 1 && header.Find(RtrSectionId.NativeLayoutInfo).Length == 32);
            Assert(header.Find(330).Start == header.Find(RtrSectionId.NativeLayoutInfo).Start);
            Assert(header.Find(RtrSectionId.EmbeddedMetadata).Length == 0);

            var snapshot = header.Sections.ToArray();
            snapshot[0] = default;

            Assert(header.Find(RtrSectionId.NativeLayoutInfo).Length == 32);
        }

        foreach (var version in new (ushort Major, ushort Minor)[] {
            (0, 0), (9, 0), (10, 0), (12, 1), (16, 1), (18, 3), (19, 0)
        }) {
            Reject<NotSupportedException>(() => NativeAotFormat.ForVersion(version.Major, version.Minor));
            Reject<NotSupportedException>(() => ReadyToRun.Read(Image(version.Major, version.Minor, false)));
        }

        Assert(NativeAotFormat.MapGrammar(9) == MapFormat.Legacy);
        Assert(NativeAotFormat.MapGrammar(12) == MapFormat.Auto);
        Assert(NativeAotFormat.MapGrammar(16) == MapFormat.Metadata);

        var unknown = ReadyToRun.Read(Image(16, 0, false, sectionId: 399));
        Assert(unknown.Find(399).Length == 32);
        Assert(unknown.Find((RtrSectionId)399).Length == 32);

        var modern = NativeAotFormat.ForVersion(16, 0);
        Reject<ArgumentOutOfRangeException>(() => modern.InvokeMapFlags(MapFormat.Auto));
        Reject<ArgumentOutOfRangeException>(() => modern.FieldMapFlags((MapFormat)255));
        Reject<ArgumentOutOfRangeException>(() =>
            ReflectionMaps.SelectFormat(16, [], [], [], new Metadata(default, 7), (MapFormat)255));

        var random = new Random(0x525452);

        for (int sample = 0; sample < 256; ++sample) {
            int[] ids = Enumerable.Range(0, random.Next(1, 96))
                .Select(_ => random.Next(1, int.MaxValue))
                .Distinct().Order().ToArray();
            var header = ReadyToRun.Read(Sections(ids));

            foreach (int id in ids)
                Assert(header.Find(id).Id == id);

            foreach (int id in new[] { 0, 330, int.MaxValue, random.Next(1, int.MaxValue) })
                Assert(header.Find(id).Id == (ids.Contains(id) ? id : 0));
        }

        Console.WriteLine("RTR formats: all six supported versions, unsupported boundaries, named/raw section identity, snapshots, invalid grammars, and 256 seeded lookup tables passed.");
    }

    private static PeImage Sections(int[] ids) {
        byte[] data = new byte[16 + ids.Length * 24 + 32];
        "RTR\0"u8.CopyTo(data);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(4), 16);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(12), (ushort)ids.Length);
        data[14] = 24;
        data[15] = 1;

        ulong start = 0x140001000UL + (uint)data.Length - 32;

        for (int i = 0; i < ids.Length; ++i) {
            var row = data.AsSpan(16 + i * 24, 24);
            BinaryPrimitives.WriteInt32LittleEndian(row, ids[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(row[4..], 1);
            BinaryPrimitives.WriteUInt64LittleEndian(row[8..], start);
            BinaryPrimitives.WriteUInt64LittleEndian(row[16..], start + 32);
        }

        return PeFixture.Create(data, ".rdata", 0x40000040);
    }

    private static PeImage Image(ushort major, ushort minor, bool lengths, int sectionId = 330) {
        byte[] data = new byte[160];
        "RTR\0"u8.CopyTo(data);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(4), major);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(6), minor);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(12), 1);
        data[14] = lengths ? (byte)16 : (byte)24;
        data[15] = 1;

        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(16), sectionId);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20), lengths ? 32U : 1U);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(24), 0x140001080);

        if (!lengths)
            BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(32), 0x1400010A0);

        return PeFixture.Create(data, ".rdata", 0x40000040);
    }

    private static void Reject<T>(Action action) where T : Exception {
        try {
            action();
        } catch (T) {
            return;
        }

        throw new Exception($"Expected {typeof(T).Name}.");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("RTR format assertion failed.");
    }
}
