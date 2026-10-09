using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using Atlas;

internal static class MethodGcCancellationChecks {
    internal static void Run(int slots = 8_000_000) {
        var warm = Create(8192);
        CheckMap(Read(warm, default), 8192);
        var source = Create(slots);
        byte[] inputHash = SHA256.HashData(source.Image.FileData);

        using (var early = new CancellationTokenSource()) {
            early.Cancel();
            Reject(() => Read(source, early.Token));
            Reject(() => MethodGcInfo.Read("\x04\x08"u8, cancellationToken: early.Token));
        }

        using (var during = new CancellationTokenSource()) {
            during.CancelAfter(20);
            long start = Stopwatch.GetTimestamp();
            MethodGcMap? completed = null;
            bool canceledAtReturn = false;

            try {
                completed = Read(source, during.Token);
                canceledAtReturn = during.IsCancellationRequested;
            } catch (OperationCanceledException) {
                Check(during.IsCancellationRequested, "The public GC producer canceled without its requested token.");
            }

            double milliseconds = Stopwatch.GetElapsedTime(start).TotalMilliseconds;

            if (completed is not null) {
                Check(!canceledAtReturn, "The public GC producer returned a completed result after cancellation.");
                CheckMap(completed, slots);
                Console.WriteLine($"Method GC public cancellation: {slots:N0} encoded slots completed "
                    + $"before cancellation in {milliseconds:F1} ms.");
            } else {
                Console.WriteLine($"Method GC public cancellation: {slots:N0} encoded slots, "
                    + $"{milliseconds:F1} ms until cancellation.");
            }
        }

        CheckMap(Read(source, default), slots);
        Check(inputHash.AsSpan().SequenceEqual(SHA256.HashData(source.Image.FileData)),
            "A canceled GC decode changed the retained PE input.");
        CheckMap(Read(warm, default), 8192);
        Console.WriteLine("Method GC cancellation: early cancellation and healthy retry preserve exact GC facts and input bytes.");
    }

    private readonly record struct Source(PeImage Image, ReadyToRun Header, UnwindTables Unwind, ManagedUnwind Managed);

    private static MethodGcMap Read(Source source, CancellationToken token) =>
        new(source.Image, source.Header, source.Unwind, source.Managed, token);

    private static void CheckMap(MethodGcMap map, int count) {
        Check(map.Version == 4 && map.MethodEntries.Length == 1, "The synthetic public GC source changed version or method count.");
        var method = map.MethodEntries[0];
        Check(method.Begin == 0x1000 && method.End == 0x1040 && method.Address == 0x2105
            && method.Error is null && method.Info is not null, "The synthetic managed method lost its GC trailer.");
        var info = method.Info!;
        Check(info.CodeLength == 1 && info.Flags == 0 && info.OutgoingStackBytes == 0
            && info.SlotEntries.Length == count && info.SafePointOffsets.IsEmpty
            && info.InterruptibleRanges.IsEmpty && info.TransitionEntries.IsEmpty,
            "The synthetic GC header or slot count changed.");

        foreach (var slot in info.SlotEntries)
            Check(slot == new MethodGcSlot(-1, 0, 0, 4), "An untracked caller-SP slot changed its independent encoded facts.");
    }

    private static Source Create(int slots) {
        if (slots < 1)
            throw new ArgumentOutOfRangeException(nameof(slots));

        byte[] blob = new byte[checked((slots * 7 + 512) / 8)];
        int bit = 0;

        void Bits(uint value, int width) {
            for (int i = 0; i < width; ++i, ++bit)
                blob[bit / 8] |= (byte)(((value >> i) & 1) << (bit % 8));
        }

        void Unsigned(uint value, int width) {
            uint mask = (1U << width) - 1;

            do {
                uint part = value & mask;
                value >>= width;
                Bits(part, width);
                Bits(value == 0 ? 0U : 1U, 1);
            } while (value != 0);
        }

        Bits(0, 2);
        Unsigned(1, 8);
        Unsigned(0, 2);
        Bits(0, 1);
        Bits(1, 1);
        Unsigned(0, 2);
        Unsigned((uint)slots, 1);
        Bits(0, 2);
        Unsigned(0, 6);
        Bits(0, 2);
        // Remaining untracked slots encode caller SP, zero delta and no flags.
        bit = checked(bit + (slots - 1) * 7);
        Check(bit <= blob.Length * 8L, "The synthetic GC slot encoding exceeds its buffer.");

        const int dataOffset = 0x240;
        byte[] bytes = new byte[checked(dataOffset + 0x110 + blob.Length)];
        void U16(int offset, ushort value) => BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(offset), value);
        void U32(int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), value);
        void U64(int offset, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset), value);

        "MZ"u8.CopyTo(bytes);
        U32(60, 64);
        "PE\0\0"u8.CopyTo(bytes.AsSpan(64));
        U16(68, 0x8664);
        U16(70, 2);
        U16(84, 240);
        U16(88, 0x20B);
        U64(112, 0x140000000);
        U32(144, checked((uint)(0x2000 + bytes.Length)));
        U32(148, 512);
        U32(196, 16);
        U32(224, 0x2080);
        U32(228, 12);
        ".managed"u8.CopyTo(bytes.AsSpan(328));
        U32(336, 64);
        U32(340, 0x1000);
        U32(344, 64);
        U32(348, 512);
        U32(364, 0x60000020);
        ".rdata"u8.CopyTo(bytes.AsSpan(368));
        U32(376, (uint)(bytes.Length - dataOffset));
        U32(380, 0x2000);
        U32(384, (uint)(bytes.Length - dataOffset));
        U32(388, dataOffset);
        U32(404, 0x40000040);
        "RTR\0"u8.CopyTo(bytes.AsSpan(dataOffset));
        U16(dataOffset + 4, 18);
        U16(dataOffset + 6, 4);
        U16(dataOffset + 12, 1);
        bytes[dataOffset + 14] = 16;
        bytes[dataOffset + 15] = 1;
        U32(dataOffset + 16, 1);
        U64(dataOffset + 24, 0x140002000);
        U32(dataOffset + 0x80, 0x1000);
        U32(dataOffset + 0x84, 0x1040);
        U32(dataOffset + 0x88, 0x2100);
        bytes[dataOffset + 0x100] = 1;
        blob.CopyTo(bytes, dataOffset + 0x105);

        var image = new PeImage(bytes);
        var header = ReadyToRun.Read(image);
        var unwind = new UnwindTables(image);
        return new(image, header, unwind, new ManagedUnwind(image, unwind, null));
    }

    private static void Reject(Action action) {
        try {
            action();
        } catch (OperationCanceledException) {
            return;
        }

        throw new Exception("The public GC producer returned a completed result after cancellation.");
    }

    private static void Check(bool value, string message) {
        if (!value)
            throw new Exception(message);
    }
}
