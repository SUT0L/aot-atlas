using System.Buffers.Binary;
using Atlas;

internal static class RtrEmptySectionChecks {
    private const ulong ImageBase = 0x140000000;
    private const ulong SectionStart = ImageBase + 0x1000;
    private const ulong SectionEnd = SectionStart + 160;

    internal static void Run() {
        foreach (bool embedded in new[] { false, true }) {
            foreach (ulong start in new[] { SectionStart, SectionEnd - 1, SectionEnd }) {
                var header = ReadyToRun.Read(Create(embedded, start, 0));
                var row = header.Find(RtrSectionId.ResourceData);

                Assert(row.Start == start && row.Length == 0);
                Assert(row.Flags == (embedded ? 0U : 1U));
            }

            foreach (ulong start in new[] { SectionStart, SectionEnd - 1 })
                Assert(ReadyToRun.Read(Create(embedded, start, 1)).Find(RtrSectionId.ResourceData).Length == 1);

            foreach (ulong start in new[] { 0UL, ImageBase - 1, SectionStart - 1, SectionEnd + 1, ulong.MaxValue })
                Reject(Create(embedded, start, 0));

            foreach (ulong start in new[] { SectionEnd, SectionEnd + 1 })
                Reject(Create(embedded, start, 1));

            Reject(Create(embedded, SectionEnd - 1, 2));
            Reject(Create(embedded, SectionStart, uint.MaxValue));

            Assert(ReadyToRun.Read(Create(embedded, ImageBase, 0)).Find(RtrSectionId.ResourceData).Start == ImageBase);
            Assert(ReadyToRun.Read(Create(embedded, ImageBase + 512, 0)).Find(RtrSectionId.ResourceData).Start == ImageBase + 512);
            Reject(Create(embedded, ImageBase + 513, 0));
        }

        Assert(ReadyToRun.Read(Create(false, SectionStart, 0, sized: false)).Find(RtrSectionId.ResourceData).Flags == 0);
        Reject(Create(false, SectionEnd, 0, sized: false));
        Reject(Create(false, SectionEnd + 1, 0, sized: false));

        var reversed = Create(false, SectionStart, 0);
        BinaryPrimitives.WriteUInt64LittleEndian(reversed.FileData.AsSpan(544), SectionStart - 1);
        Reject(reversed);

        Console.WriteLine("RTR empty sections: sized boundary addresses, nonempty extents, unsized symbols, header boundaries, and reversed legacy ranges passed.");
    }

    private static PeImage Create(bool embedded, ulong start, uint length, bool sized = true) {
        byte[] data = new byte[160];
        "RTR\0"u8.CopyTo(data);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(4), embedded ? (ushort)18 : (ushort)16);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(6), embedded ? (ushort)4 : (ushort)0);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(12), 1);
        data[14] = embedded ? (byte)16 : (byte)24;
        data[15] = 1;

        var row = data.AsSpan(16);
        BinaryPrimitives.WriteInt32LittleEndian(row, (int)RtrSectionId.ResourceData);
        BinaryPrimitives.WriteUInt32LittleEndian(row[4..], embedded ? length : sized ? 1U : 0U);
        BinaryPrimitives.WriteUInt64LittleEndian(row[8..], start);

        if (!embedded)
            BinaryPrimitives.WriteUInt64LittleEndian(row[16..], sized ? unchecked(start + length) : 0);

        return PeFixture.Create(data, ".rdata", 0x40000040);
    }

    private static void Reject(PeImage image) {
        try {
            ReadyToRun.Read(image);
        } catch (InvalidDataException) {
            return;
        }

        throw new Exception("Malformed RTR section was accepted.");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("RTR empty section assertion failed.");
    }
}
