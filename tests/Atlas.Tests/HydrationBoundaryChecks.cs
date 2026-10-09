using System.Buffers.Binary;
using Atlas;

internal static class HydrationBoundaryChecks {
    private const ulong CommandBase = 0x140001100;
    private const ulong Destination = 0x140001080;

    internal static void Run() {
        foreach (bool embedded in new[] { false, true }) {
            foreach (int trailing in new[] { 0, 1, 4 }) {
                Check(Create(embedded, [], [], trailing), []);
                Check(Create(embedded, [0x18, 0xAA, 0xBB, 0xCC], [], trailing), [0xAA, 0xBB, 0xCC]);
                Check(Create(embedded, [0x21], [], trailing), new byte[4]);

                int prefix = embedded ? 8 : 4;
                byte[] inline = [0x0C, 0, 0, 0, 0, 0x0D, 0, 0, 0, 0];
                BinaryPrimitives.WriteInt32LittleEndian(inline.AsSpan(1), -prefix - 1);
                BinaryPrimitives.WriteInt32LittleEndian(inline.AsSpan(6), -prefix - 6);
                byte[] expected = new byte[12];
                BinaryPrimitives.WriteInt32LittleEndian(expected, checked((int)(CommandBase - Destination)));
                BinaryPrimitives.WriteUInt64LittleEndian(expected.AsSpan(4), CommandBase);

                Check(Create(embedded, inline, [], trailing), expected);
            }

            foreach (byte opcode in new byte[] { 2, 3 }) {
                foreach (int tableLength in new[] { 0, 1, 3 })
                    Reject(Create(embedded, [opcode], new byte[tableLength]));

                int prefix = embedded ? 8 : 4;
                byte[] fixups = new byte[4];
                BinaryPrimitives.WriteInt32LittleEndian(fixups, -prefix - 1);
                byte[] expected = new byte[opcode == 2 ? 4 : 8];

                if (opcode == 2)
                    BinaryPrimitives.WriteInt32LittleEndian(expected, checked((int)(CommandBase - Destination)));
                else
                    BinaryPrimitives.WriteUInt64LittleEndian(expected, CommandBase);

                Check(Create(embedded, [opcode], fixups), expected);

                // Embedded rows bound their table; unrelated bytes after the row cannot supply a relocation.
                if (embedded)
                    Reject(Create(embedded, [opcode], [], trailing: 4));

                Reject(Create(embedded, [(byte)(opcode | (1 << 3))], fixups));
            }

            foreach (byte[] malformed in new byte[][] {
                [6], [7], [0xE8], [0xF0, 0], [0xF8, 0, 0], [0x18, 1], [0x0D, 0, 0, 0]
            })
                Reject(Create(embedded, malformed, []));

            foreach (int payload in new[] { 28, 29, 120 }) {
                byte[] commands = payload == 28 ? [0xE1] : [0xE9, (byte)(payload - 28)];
                Check(Create(embedded, commands, []), new byte[payload]);
            }

            int headerLength = embedded ? 8 : 4;

            for (int length = 1; length < headerLength; ++length) {
                var truncated = Create(embedded, [], []);

                if (embedded)
                    BinaryPrimitives.WriteUInt32LittleEndian(truncated.FileData.AsSpan(532), (uint)length);
                else
                    BinaryPrimitives.WriteUInt64LittleEndian(truncated.FileData.AsSpan(544), CommandBase + (uint)length);

                Reject(truncated);
            }

            if (embedded) {
                foreach (int commandEnd in new[] { -1, 7, 10 }) {
                    var invalidLength = Create(true, [0x21], []);
                    BinaryPrimitives.WriteInt32LittleEndian(invalidLength.FileData.AsSpan(772), commandEnd);
                    Reject(invalidLength);
                }
            }

            Reject(Create(embedded, [0xFB, 0xFF, 0xFF, 0xFF], []));
            Reject(Create(embedded, [0xE9, 200], []));

            var beyondFile = Create(embedded, [0x21], []);
            uint virtualSize = beyondFile.Sections[0].VirtualSize + 16;
            BinaryPrimitives.WriteUInt32LittleEndian(beyondFile.FileData.AsSpan(336), virtualSize);
            BinaryPrimitives.WriteUInt32LittleEndian(beyondFile.FileData.AsSpan(144), 0x1000 + virtualSize);

            if (embedded)
                BinaryPrimitives.WriteUInt32LittleEndian(beyondFile.FileData.AsSpan(532), (uint)(headerLength + 2));
            else
                BinaryPrimitives.WriteUInt64LittleEndian(beyondFile.FileData.AsSpan(544), CommandBase + (uint)headerLength + 2);

            Reject(new PeImage(beyondFile.FileData));
        }

        // A table cannot borrow bytes from an adjacent PE section.
        var adjacent = Create(false, [3], []);
        byte[] file = new byte[adjacent.FileData.Length + 4];
        adjacent.FileData.CopyTo(file, 0);
        uint nextRva = 0x1000 + (uint)adjacent.Sections[0].FileSize;
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(70), 2);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(144), nextRva + 4);
        ".rdata"u8.CopyTo(file.AsSpan(368));
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(376), 4);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(380), nextRva);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(384), 4);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(388), (uint)adjacent.FileData.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(404), 0x40000040);
        Reject(new PeImage(file));

        Console.WriteLine("Hydration boundaries: empty tables, all command classes, missing entries, bounded embedded tables, and malformed commands passed.");
    }

    private static PeImage Create(bool embedded, byte[] commands, byte[] fixups, int trailing = 0) {
        int prefix = embedded ? 8 : 4;
        int commandLength = prefix + commands.Length;
        byte[] data = new byte[256 + commandLength + fixups.Length + trailing];
        "RTR\0"u8.CopyTo(data);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(4), embedded ? (ushort)18 : (ushort)16);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(6), embedded ? (ushort)4 : (ushort)0);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(12), 1);
        data[14] = embedded ? (byte)16 : (byte)24;
        data[15] = 1;

        var row = data.AsSpan(16);
        BinaryPrimitives.WriteInt32LittleEndian(row, (int)RtrSectionId.DehydratedData);
        BinaryPrimitives.WriteUInt32LittleEndian(row[4..], embedded ? (uint)(commandLength + fixups.Length) : 1);
        BinaryPrimitives.WriteUInt64LittleEndian(row[8..], CommandBase);

        if (!embedded)
            BinaryPrimitives.WriteUInt64LittleEndian(row[16..], CommandBase + (uint)commandLength);

        var encoded = data.AsSpan(256);
        BinaryPrimitives.WriteInt32LittleEndian(encoded, checked((int)((long)Destination - (long)CommandBase)));

        if (embedded)
            BinaryPrimitives.WriteInt32LittleEndian(encoded[4..], commandLength);

        commands.CopyTo(encoded[prefix..]);
        fixups.CopyTo(encoded[commandLength..]);

        return PeFixture.Create(data, ".data", 0xC0000040);
    }

    private static void Check(PeImage image, byte[] expected) {
        var result = Hydration.Read(image, ReadyToRun.Read(image));

        if (result.Start != Destination || !result.Bytes.SequenceEqual(expected))
            throw new Exception("Unexpected hydration boundary output.");
    }

    private static void Reject(PeImage image) {
        try {
            Hydration.Read(image, ReadyToRun.Read(image));
        } catch (InvalidDataException) {
            return;
        }

        throw new Exception("Malformed hydration boundary input was accepted.");
    }
}
