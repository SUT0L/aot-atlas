using System.Buffers.Binary;
using Atlas;

internal static class ManagedUnwindChecks {
    internal static void Run() {
        const int delta = 512 - 0x1000;
        byte[] bytes = new byte[0x1000];
        "MZ"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(60), 64);
        "PE\0\0"u8.CopyTo(bytes.AsSpan(64));
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(68), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(70), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(84), 240);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(88), 0x20B);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(112), 0x140000000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(144), 0x2000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(148), 512);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(196), 16);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(224), 0x1200);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(228), 48);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(248), 0x1600);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(252), 28);
        ".text"u8.CopyTo(bytes.AsSpan(328));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(336), 0xE00);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(340), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(344), 0xE00);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(348), 512);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(364), 0x60000020);

        uint[] begin = [0x1010, 0x1040, 0x1060, 0x1080], end = [0x1040, 0x1060, 0x1080, 0x10A0];
        for (int i = 0; i < 4; ++i) {
            var row = bytes.AsSpan(0x1200 + delta + i * 12);
            BinaryPrimitives.WriteUInt32LittleEndian(row, begin[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(row[4..], end[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(row[8..], (uint)(0x1300 + i * 32));
            bytes[0x1300 + delta + i * 32] = 1;
        }
        bytes[0x1300 + delta] = 9;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x1304 + delta), 0x1100);
        bytes[0x1308 + delta] = 4;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x1309 + delta), 0x1400);
        bytes[0x1322 + delta] = 1;
        bytes[0x1326 + delta] = 1;
        bytes[0x1344 + delta] = 2;
        bytes[0x1364 + delta] = 16;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x1365 + delta), 0x1500);
        bytes[0x1500 + delta] = 1;
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(0x1501 + delta), 0x1010 - 0x1501);
        new byte[] { 6, 8, 96, 96, 0, 0x17, 0, 0, 0, 2, 0, 16, 68, 96, 160 }.CopyTo(bytes, 0x1400 + delta);

        var debug = bytes.AsSpan(0x1600 + delta);
        BinaryPrimitives.WriteUInt32LittleEndian(debug[12..], 13);
        BinaryPrimitives.WriteUInt32LittleEndian(debug[16..], 28);
        BinaryPrimitives.WriteUInt32LittleEndian(debug[20..], 0x1640);
        BinaryPrimitives.WriteUInt32LittleEndian(debug[24..], 0x1640 + delta);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x1644 + delta), 0x1010);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x1648 + delta), 0x90);
        ".managedcode$I\0"u8.CopyTo(bytes.AsSpan(0x164C + delta));

        PeDebugChecks.Run(bytes);

        var image = new PeImage(bytes);
        var result = new ManagedUnwind(image, new UnwindTables(image), new PeDebug(image));
        Assert(result.RegionSource == ManagedRegionSource.Pogo && result.RegionStart == 0x1010 && result.RegionLength == 0x90);
        Assert(result.Frames.Length == 4 && result.Frames[0].FrameCount == 3 && result.Frames[3].FrameCount == 1);
        Assert(result.Frames[0].Trailer == 0x1308 && result.Frames[0].HeaderLength == 5);
        Assert(result.Frames[1].Trailer == 0x1326 && result.Frames[1].Root == 1 && result.Frames[2].Root == 1);
        Assert(result.Frames[3].Root == 4 && result.Frames[3].UnboxingTarget == 0x1010);
        Assert(result.Exceptions.Length == 1 && result.Exceptions[0].Length == 15 && result.Clauses.Length == 3);
        Assert(result.Clauses[0].Kind == ExceptionClauseKind.Typed && result.Clauses[0].Type == 0x1700);
        Assert(result.Clauses[0].TryStart == 4 && result.Clauses[0].TryEnd == 16 && result.Clauses[0].HandlerOffset == 48);
        Assert(result.Clauses[1].Kind == ExceptionClauseKind.Marker);
        Assert(result.Clauses[2].Kind == ExceptionClauseKind.Filter && result.Clauses[2].FilterOffset == 80);

        byte[] emptyRanges = (byte[])bytes.Clone();
        emptyRanges[0x1402 + delta] = 0;
        emptyRanges[0x140C + delta] = 4;
        image = new PeImage(emptyRanges);
        result = new ManagedUnwind(image, new UnwindTables(image), new PeDebug(image));
        Assert(result.Clauses[0].TryStart == 4 && result.Clauses[0].TryEnd == 4);
        Assert(result.Clauses[0].Kind == ExceptionClauseKind.Typed && result.Clauses[0].HandlerOffset == 48);
        Assert(result.Clauses[2].TryStart == 8 && result.Clauses[2].TryEnd == 8);
        Assert(result.Clauses[2].Kind == ExceptionClauseKind.Filter && result.Clauses[2].FilterOffset == 80);

        foreach (uint signature in new uint[] { 0x4C544347, 0x50474900, 0x50475500, 0x5350474F }) {
            byte[] variant = (byte[])bytes.Clone();
            BinaryPrimitives.WriteUInt32LittleEndian(variant.AsSpan(0x1640 + delta), signature);
            image = new PeImage(variant);
            result = new ManagedUnwind(image, new UnwindTables(image), new PeDebug(image));
            Assert(result.Frames.Length == 4 && result.Clauses.Length == 3);
        }

        byte[] stripped = (byte[])bytes.Clone();
        stripped.AsSpan(248, 8).Clear();
        image = new PeImage(stripped);
        result = new ManagedUnwind(image, new UnwindTables(image), new PeDebug(image));
        Assert(result.RegionSource == ManagedRegionSource.Unknown && result.Frames.Length == 0);
        ".managed"u8.CopyTo(stripped.AsSpan(328));
        image = new PeImage(stripped);
        result = new ManagedUnwind(image, new UnwindTables(image), new PeDebug(image));
        Assert(result.RegionSource == ManagedRegionSource.Section && result.Frames.Length == 4 && result.Clauses.Length == 3);

        for (int fault = 0; fault < 11; ++fault) {
            byte[] invalid = (byte[])bytes.Clone();
            switch (fault) {
                case 0:
                    invalid[0x1308 + delta] = 1;
                    break;
                case 1:
                    invalid[0x1308 + delta] = 32;
                    break;
                case 2:
                    invalid[0x1500 + delta] = 2;
                    break;
                case 3:
                    invalid[0x1400 + delta] = 31;
                    break;
                case 4:
                    invalid[0x1402 + delta] = 102;
                    break;
                case 5:
                    BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(0x1404 + delta), 0x9000);
                    break;
                case 6:
                    invalid[0x1403 + delta] = 254;
                    break;
                case 7:
                    invalid[0x1403 + delta] = 100;
                    break;
                case 8:
                    invalid[0x164C + delta] = 128;
                    break;
                case 9:
                    BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(252), 27);
                    break;
                case 10:
                    BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(0x1640 + delta), uint.MaxValue);
                    break;
            }
            bool failed = false;
            try {
                image = new PeImage(invalid);
                _ = new ManagedUnwind(image, new UnwindTables(image), new PeDebug(image));
            } catch (InvalidDataException) { failed = true; } catch (NotSupportedException) { failed = true; }
            Assert(failed);
        }
        Console.WriteLine("Managed unwind: personality tails, unaligned trailers, root/handler/filter links, EH markers, unboxing targets and malformed records passed.");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Managed unwind assertion failed.");
    }
}
