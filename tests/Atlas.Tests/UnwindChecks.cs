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

    private static void Assert(bool condition) {
        if (!condition)
            throw new Exception("Unwind assertion failed.");
    }
}
