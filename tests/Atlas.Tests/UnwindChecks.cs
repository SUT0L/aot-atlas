using System.Buffers.Binary;
using Atlas;

internal static class UnwindChecks {
    internal static void Run() {
        const int count = 1024, directory = 0x8000, infoStart = 0xD000;
        byte[] bytes = new byte[0x20000];
        "MZ"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(60), 64);
        "PE\0\0"u8.CopyTo(bytes.AsSpan(64));
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(68), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(70), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(84), 240);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(88), 0x20B);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(112), 0x140000000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(144), 0x21000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(148), 512);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(196), 16);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(224), directory);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(228), count * 12);
        ".text"u8.CopyTo(bytes.AsSpan(328));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(336), (uint)bytes.Length - 512);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(340), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(344), (uint)bytes.Length - 512);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(348), 512);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(364), 0x60000020);
        const int fileDelta = 512 - 0x1000;
        var random = new Random(0x51A7C);
        int[] roots = new int[count];
        for (int i = 0; i < count; ++i) {
            int kind = i == 0 ? 0 : random.Next(3);
            int parent = i == 0 ? 0 : random.Next(i);
            uint unwind = (uint)(infoStart + i * 32);
            var info = bytes.AsSpan((int)unwind + fileDelta, 32);
            info[0] = (byte)(random.Next(1, 3) | (kind == 1 ? 32 : 0));
            info[1] = 4;
            info[2] = (byte)random.Next(2);
            info[4] = 4;
            info[5] = 2;
            if (kind == 1) {
                int tail = info[2] == 0 ? 4 : 8;
                bytes.AsSpan(directory + parent * 12 + fileDelta, 12).CopyTo(info[tail..]);
            } else if (kind == 2) {
                unwind = (uint)(directory + parent * 12) | 1;
            }

            var row = bytes.AsSpan(directory + i * 12 + fileDelta, 12);
            BinaryPrimitives.WriteUInt32LittleEndian(row, (uint)(0x1000 + i * 16));
            BinaryPrimitives.WriteUInt32LittleEndian(row[4..], (uint)(0x1008 + i * 16));
            BinaryPrimitives.WriteUInt32LittleEndian(row[8..], unwind);
            roots[i] = kind == 0 ? i : roots[parent];
        }

        var result = new UnwindTables(new PeImage(bytes));
        Assert(result.DirectoryCount == count);
        for (int i = 0; i < count; ++i) {
            var root = result.Entries[result.Entries[i].Root - 1];
            Assert(root.Function.Begin == 0x1000 + roots[i] * 16 && root.Parent == 0);
        }

        int firstRow = directory + fileDelta;
        int secondRow = firstRow + 12;
        byte[] invalidDiagnostic = (byte[])bytes.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(invalidDiagnostic.AsSpan(secondRow + 4), 0x1010);
        string diagnostic = FunctionError(invalidDiagnostic);
        Assert(diagnostic.Contains("exception row 1 (directory RVA 0x00008000, row RVA 0x0000800C)", StringComparison.Ordinal));
        Assert(diagnostic.Contains("Begin=0x00001010, End=0x00001010, Unwind=0x0000D020, PreviousBegin=0x00001000", StringComparison.Ordinal));
        Assert(diagnostic.EndsWith("BeginAddress is not below EndAddress.", StringComparison.Ordinal));

        CheckFunctionError(bytes, invalid => {
            BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(secondRow), 0x0FF8);
            BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(secondRow + 4), 0x1000);
        }, "BeginAddress is below the previous BeginAddress.");
        CheckFunctionError(bytes, invalid => {
            BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(firstRow), 0x30000);
            BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(firstRow + 4), 0x30010);
        }, "Code range is not mapped within one region");
        CheckFunctionError(bytes, invalid =>
            BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(364), 0x40000020),
            "BeginAddress is not executable (section \".text\" RVA 0x00001000-0x00020E00, characteristics 0x40000020).");
        CheckFunctionError(bytes, invalid =>
            BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(firstRow + 8), 0),
            "UnwindInfoAddress is zero.");
        CheckFunctionError(bytes, invalid =>
            BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(firstRow + 8), 2),
            "UnwindInfoAddress has reserved bit 1 set.");
        CheckFunctionError(bytes, invalid =>
            BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(firstRow + 8), 0x30000),
            "Unwind information header is not mapped");

        const int externalEntry = 0x1F000;
        byte[] invalidReference = (byte[])bytes.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(invalidReference.AsSpan(firstRow + 8), externalEntry | 1);
        int externalOffset = externalEntry + fileDelta;
        BinaryPrimitives.WriteUInt32LittleEndian(invalidReference.AsSpan(externalOffset), 0x2000);
        BinaryPrimitives.WriteUInt32LittleEndian(invalidReference.AsSpan(externalOffset + 4), 0x2000);
        BinaryPrimitives.WriteUInt32LittleEndian(invalidReference.AsSpan(externalOffset + 8), infoStart);
        diagnostic = UnwindError(invalidReference);
        Assert(diagnostic.Contains("indirect or chained record at RVA 0x0001F000", StringComparison.Ordinal));
        Assert(diagnostic.Contains("Begin=0x00002000, End=0x00002000, Unwind=0x0000D000", StringComparison.Ordinal));
        Assert(diagnostic.EndsWith("BeginAddress is not below EndAddress.", StringComparison.Ordinal));

        for (int fault = 0; fault < 6; ++fault) {
            byte[] invalid = (byte[])bytes.Clone();
            if (fault == 0)
                BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(directory + fileDelta + 8), directory | 1);
            else if (fault == 1)
                invalid[infoStart + fileDelta] = 57;
            else if (fault == 2)
                BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(directory + fileDelta + 8), 2);
            else if (fault == 3)
                BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(228), count * 12 - 1);
            else if (fault == 4)
                invalid[infoStart + fileDelta] = 3;
            else
                BinaryPrimitives.WriteUInt32LittleEndian(invalid.AsSpan(directory + fileDelta + 8), (directory + 4) | 1);

            bool failed = false;
            try {
                _ = new UnwindTables(new PeImage(invalid));
            } catch (InvalidDataException) { failed = true; } catch (NotSupportedException) { failed = true; }
            Assert(failed);
        }
        Console.WriteLine("Unwind: 1024 seeded direct, indirect and chained ranges match the reference roots; cycles and invalid records rejected.");
    }

    private static void CheckFunctionError(byte[] valid, Action<byte[]> corrupt, string expected) {
        byte[] invalid = (byte[])valid.Clone();
        corrupt(invalid);
        Assert(FunctionError(invalid).Contains(expected, StringComparison.Ordinal));
    }

    private static string FunctionError(byte[] bytes) {
        try {
            _ = RuntimeTables.Functions(new PeImage(bytes));
        } catch (InvalidDataException error) {
            return error.Message;
        }
        throw new Exception("Malformed runtime function was accepted.");
    }

    private static string UnwindError(byte[] bytes) {
        try {
            _ = new UnwindTables(new PeImage(bytes));
        } catch (InvalidDataException error) {
            return error.Message;
        }
        throw new Exception("Malformed unwind record was accepted.");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("Unwind assertion failed.");
    }
}
