using System.Buffers.Binary;
using System.Reflection.PortableExecutable;
using System.Text;
using Atlas;

internal static class PeDebugChecks {
    internal static void Run(byte[] fixture) {
        const int delta = 512 - 0x1000;
        byte[] bytes = (byte[])fixture.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(252), 56);
        var row = bytes.AsSpan(0x161C + delta, 28);
        BinaryPrimitives.WriteUInt32LittleEndian(row[12..], 2);
        byte[] path = Encoding.UTF8.GetBytes("build/" + new string('x', 300) + "/📎.pdb");
        int length = 25 + path.Length;
        BinaryPrimitives.WriteUInt32LittleEndian(row[16..], (uint)length);
        BinaryPrimitives.WriteUInt32LittleEndian(row[24..], 0x1680 + delta);
        var data = bytes.AsSpan(0x1680 + delta, length);
        "RSDS"u8.CopyTo(data);
        var guid = new Guid("00112233-4455-6677-8899-aabbccddeeff");
        guid.TryWriteBytes(data[4..]);
        BinaryPrimitives.WriteUInt32LittleEndian(data[20..], 0xFEDCBA98);
        path.CopyTo(data[24..]);

        var parsed = new PeDebug(new PeImage(bytes));
        var actual = parsed.CodeViews.Single();
        using var reader = new PEReader(new MemoryStream(bytes));
        var expected = reader.ReadCodeViewDebugDirectoryData(
            reader.ReadDebugDirectory().Single(entry => entry.Type == DebugDirectoryEntryType.CodeView));
        Assert(actual.Rsds && actual.PathUtf8Valid && actual.Guid == expected.Guid && actual.Guid == guid);
        Assert(actual.Age == unchecked((uint)expected.Age) && actual.Rva == 0);
        Assert(actual.RecordFileOffset == 0x161C + delta && actual.Data.Count == length);
        Assert(bytes.AsSpan(actual.Path.Start, actual.Path.Count).SequenceEqual(Encoding.UTF8.GetBytes(expected.Path)));
        Assert(parsed.Entries.Count == 1);

        BinaryPrimitives.WriteUInt32LittleEndian(row[20..], 0x1680);
        Assert(new PeDebug(new PeImage(bytes)).CodeViews.Single().Guid == guid);
        data[24] = 0xFF;
        actual = new PeDebug(new PeImage(bytes)).CodeViews.Single();
        Assert(!actual.PathUtf8Valid && actual.Path.Count == path.Length);
        data[24] = path[0];

        "NB10"u8.CopyTo(data);
        actual = new PeDebug(new PeImage(bytes)).CodeViews.Single();
        Assert(!actual.Rsds && actual.Path.Count == 0 && actual.Guid == default && actual.Age == 0);
        Assert(actual.Data.Count == length);
        "RSDS"u8.CopyTo(data);

        for (int fault = 0; fault < 4; ++fault) {
            byte[] invalid = (byte[])bytes.Clone();
            if (fault == 0)
                BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(0x162C + delta), 24);
            else if (fault == 1)
                invalid[0x1680 + delta + length - 1] = 1;
            else if (fault == 2)
                BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(0x1630 + delta), 0x1681);
            else
                BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(0x1634 + delta), (uint)invalid.Length - 1);

            bool rejected = false;
            try {
                _ = new PeDebug(new PeImage(invalid));
            } catch (InvalidDataException) {
                rejected = true;
            }
            Assert(rejected);
        }
        Console.WriteLine("CodeView: Microsoft PEReader identity/path match, long UTF-8 paths, unmapped data, invalid UTF-8, unknown formats and malformed extents passed.");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("CodeView assertion failed.");
    }
}
