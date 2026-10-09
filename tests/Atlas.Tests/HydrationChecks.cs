using Atlas;
using System.Buffers.Binary;

internal static class HydrationChecks {
    private const ulong ImageBase = 0x140000000;
    private const uint CommandRva = 0x1100;
    private const uint DestinationRva = 0x3000;

    internal static void Run() {
        foreach (bool embedded in new[] { false, true }) {
            byte[] mixed = [0x18, 0xAA, 0xBB, 0xCC, 0x11, 0x03, 0x02, 0x0D, 0, 0, 0, 0, 0x0C, 0, 0, 0, 0];
            int header = embedded ? 8 : 4;
            BinaryPrimitives.WriteInt32LittleEndian(mixed.AsSpan(8), -8);
            BinaryPrimitives.WriteInt32LittleEndian(
                mixed.AsSpan(13), (int)DestinationRva - (int)CommandRva - header - 13);
            var image = Create(mixed, embedded, 64 * 1024 * 1024);

            long allocated = GC.GetAllocatedBytesForCurrentThread();

            var result = Hydration.Read(image, ReadyToRun.Read(image));

            allocated = GC.GetAllocatedBytesForCurrentThread() - allocated;

            byte[] expected = new byte[29];
            expected[0] = 0xAA;
            expected[1] = 0xBB;
            expected[2] = 0xCC;
            BinaryPrimitives.WriteUInt64LittleEndian(expected.AsSpan(5), ImageBase + 0x6000);
            BinaryPrimitives.WriteInt32LittleEndian(expected.AsSpan(13), 0x6000 - (int)DestinationRva - 13);
            BinaryPrimitives.WriteUInt64LittleEndian(expected.AsSpan(17), ImageBase + CommandRva + (uint)header);
            BinaryPrimitives.WriteInt32LittleEndian(expected.AsSpan(25), -25);

            Assert(result.Start == ImageBase + DestinationRva && result.Bytes.SequenceEqual(expected));
            Assert(result.Storage.Length == 29 && allocated < 4096);

            foreach (byte[] malformed in new byte[][] {
                [6], [7], [0xE8], [0xF0, 0], [0xF8, 0, 0], [0x18, 1], [0x0D, 0, 0, 0]
            }) {
                var malformedImage = Create(malformed, embedded, 64 * 1024 * 1024);

                Reject(() => Hydration.Read(malformedImage, ReadyToRun.Read(malformedImage)));
            }

            foreach (int payload in new[] { 28, 29, 283, 284, 65563, 65564 }) {
                int extra = payload <= 28 ? 0 : payload <= 283 ? 1 : payload <= 65563 ? 2 : 3;
                byte[] zero = new byte[extra + 1];
                zero[0] = (byte)(1 | ((extra == 0 ? payload : 28 + extra) << 3));

                for (int i = 0; i < extra; ++i)
                    zero[i + 1] = (byte)((payload - 28) >> (i * 8));

                var zeroImage = Create(zero, embedded, 64 * 1024 * 1024);
                var zeroResult = Hydration.Read(zeroImage, ReadyToRun.Read(zeroImage));

                Assert(zeroResult.Storage.Length == payload && zeroResult.Bytes.IndexOfAnyExcept((byte)0) == -1);
            }

            byte[] huge = new byte[128 * 4];

            for (int i = 0; i < huge.Length; i += 4) {
                huge[i] = 0xf9;
                huge.AsSpan(i + 1, 3).Fill(0xff);
            }

            var beyondArray = Create(huge, embedded, uint.MaxValue - 0x1000);
            Reject(() => Hydration.Read(beyondArray, ReadyToRun.Read(beyondArray)));

            var oversized = Create([0xE1], embedded, DestinationRva - 0x1000 + 16); // 28 bytes of zero-fill, only 16 mapped
            Reject(() => Hydration.Read(oversized, ReadyToRun.Read(oversized)));

            byte[] lateFixup = [0xF9, 0xFF, 0xFF, 0xFF, 0xF9, 0xFF, 0xFF, 0xFF, 0xFB, 0xFF, 0xFF, 0xFF];
            byte[] lateRelativeOverflow = [0xF9, 0xFF, 0xFF, 0xFF, 0xF9, 0xFF, 0xFF, 0xFF, 0x0C, 0, 0, 0, 0x80];

            RejectBeforeOutputAllocation(Create(lateFixup, embedded, 128 * 1024 * 1024), typeof(InvalidDataException));
            RejectBeforeOutputAllocation(Create(lateRelativeOverflow, embedded, 128 * 1024 * 1024), typeof(OverflowException));

            var invalidFixup = Create([0xFB, 0xFF, 0xFF, 0xFF], embedded, 64 * 1024 * 1024);
            Reject(() => Hydration.Read(invalidFixup, ReadyToRun.Read(invalidFixup)));
        }

        Reject(() => Hydration.Expand([0], -1, [], 0, 0, 0, new byte[1]));
        Reject(() => Hydration.Expand([0], 2, [], 0, 0, 0, new byte[1]));
        Assert(Hydration.Expand([], 0, [], 0, 0, 0, []) == 0);
    }

    private static PeImage Create(byte[] commands, bool embedded, uint virtualSize) {
        byte[] bytes = new byte[512 + 4096];
        "MZ"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(60), 64);
        "PE\0\0"u8.CopyTo(bytes.AsSpan(64));
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(68), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(70), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(84), 240);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(88), 0x20b);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(112), ImageBase);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(144), 0x1000 + virtualSize);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(148), 512);

        ".data"u8.CopyTo(bytes.AsSpan(328));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(336), virtualSize);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(340), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(344), 4096);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(348), 512);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(364), 0xC0000040);

        "RTR\0"u8.CopyTo(bytes.AsSpan(512));
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(516), embedded ? (ushort)18 : (ushort)16);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(518), embedded ? (ushort)4 : (ushort)0);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(524), 1);
        bytes[526] = embedded ? (byte)16 : (byte)24;
        bytes[527] = 1;

        int prefix = embedded ? 8 : 4;
        int commandLength = prefix + commands.Length;
        var row = bytes.AsSpan(528);
        BinaryPrimitives.WriteInt32LittleEndian(row, 207);
        BinaryPrimitives.WriteUInt32LittleEndian(row[4..], embedded ? (uint)(commandLength + 4) : 1);
        BinaryPrimitives.WriteUInt64LittleEndian(row[8..], ImageBase + CommandRva);

        if (!embedded)
            BinaryPrimitives.WriteUInt64LittleEndian(row[16..], ImageBase + CommandRva + (uint)commandLength);

        var encoded = bytes.AsSpan(512 + 256);
        BinaryPrimitives.WriteInt32LittleEndian(encoded, (int)(DestinationRva - CommandRva));

        if (embedded)
            BinaryPrimitives.WriteInt32LittleEndian(encoded[4..], commandLength);

        commands.CopyTo(encoded[prefix..]);
        BinaryPrimitives.WriteInt32LittleEndian(encoded[commandLength..], 0x6000 - (int)CommandRva - commandLength);

        return new PeImage(bytes);
    }

    private static void RejectBeforeOutputAllocation(PeImage image, Type expectedError) {
        var header = ReadyToRun.Read(image);
        long allocated = GC.GetAllocatedBytesForCurrentThread();

        try {
            Hydration.Read(image, header);
        } catch (Exception error) when (error.GetType() == expectedError) {
            Assert(GC.GetAllocatedBytesForCurrentThread() - allocated < 16 * 1024);
            return;
        }

        throw new Exception("Malformed hydration allocated output or was accepted.");
    }

    private static void Reject(Action action) {
        try {
            action();
        } catch (InvalidDataException) {
            return;
        }

        throw new Exception("Malformed dehydration was accepted.");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("Hydration assertion failed.");
    }
}
